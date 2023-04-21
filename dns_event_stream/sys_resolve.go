package dns_event_stream

import (
	"bufio"
	"net"
	"os"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/miekg/dns"
	"github.com/rs/zerolog"
)

type SysResolverSubject struct {
	NameServers   []string
	Log           *zerolog.Logger
	ResolvConf    *string
	Timeout       time.Duration
	Question      dns.Question
	activeSubject *ActiveSubject
	request       int
}

func append53(addr string) (string, int, error) {
	host, portStr, err := net.SplitHostPort(addr)
	if err != nil && !strings.HasSuffix(err.Error(), "missing port in address") {
		return "", 0, err
	} else {
		host = addr
	}
	port := 53
	if portStr != "" {
		my, err := strconv.Atoi(portStr)
		if err != nil {
			return "", 0, err
		}
		port = my
	}
	return host, port, nil
}

func (r *SysResolverSubject) ConnectActiveSubject(as *ActiveSubject) {
	r.activeSubject = as
}

func (r *SysResolverSubject) Key() dns.Question {
	return r.Question
}

func (r *SysResolverSubject) defaultTimeout() time.Duration {
	if r.Timeout == 0 {
		return 200 * time.Millisecond
	}
	return r.Timeout
}

func (r *SysResolverSubject) ensureLog() *zerolog.Logger {
	if r.Log == nil {
		if r.activeSubject == nil || r.activeSubject.Log == nil {
			zlog := zerolog.New(os.Stderr).With().Timestamp().Logger()
			r.Log = &zlog
		} else {
			r.Log = r.activeSubject.Log
		}
		zlog := r.Log.With().Str("subject", r.Question.String()).Logger()
		r.Log = &zlog
	}
	return r.Log
}

var reSpace = regexp.MustCompile(`\s+`)

func (r *SysResolverSubject) readResolvConf() ([]string, error) {
	if r.ResolvConf == nil {
		resolvConfFile := "/etc/resolv.conf"
		r.ResolvConf = &resolvConfFile
	}

	resolvFile, err := os.Open(*r.ResolvConf)
	if err != nil {
		return nil, err
	}
	defer resolvFile.Close()
	fileScanner := bufio.NewScanner(resolvFile)
	fileScanner.Split(bufio.ScanLines)
	out := make([]string, 0)
	for fileScanner.Scan() {
		line := strings.TrimSpace(fileScanner.Text())
		tokens := reSpace.Split(line, -1)
		if len(tokens) > 1 {
			if tokens[0] == "nameserver" {
				out = append(out, tokens[1])
			}
		}
	}
	if len(out) == 0 {
		out = []string{"127.0.0.1", "[::1]"}
	}
	return out, nil
}

func (r *SysResolverSubject) Resolve() ([]dns.RR, error) {
	port := 53
	r.request++
	var ip string
	if len(r.NameServers) == 0 {
		var err error
		r.ensureLog().Info().Msg("reading resolv.conf")
		r.NameServers, err = r.readResolvConf()
		if err != nil {
			return nil, err
		}
	}
	var err error
	ip, port, err = append53(r.NameServers[r.request%len(r.NameServers)])
	if err != nil {
		return nil, err
	}
	r.ensureLog().Debug().Str("ip", ip).Int("port", port).Strs("nameservers", r.NameServers).Msg("using nameserver")

	c := dns.Client{
		Dialer: &net.Dialer{
			Timeout: r.defaultTimeout(),
		},
	}
	m1 := dns.Msg{}
	m1.Id = dns.Id()
	m1.RecursionDesired = true
	m1.Question = []dns.Question{r.Question}
	in, rtt, err := c.Exchange(&m1, net.JoinHostPort(ip, strconv.Itoa(port)))
	if err != nil {
		r.ensureLog().Error().
			Str("dns_server", net.JoinHostPort(ip, strconv.Itoa(port))).
			Str("name", r.Question.Name).
			Str("type", dns.TypeToString[r.Question.Qtype]).
			Str("class", dns.ClassToString[r.Question.Qclass]).
			Err(err).Msg("exchange")
		return nil, err
	}

	r.ensureLog().Debug().Str("name", r.Question.Name).
		Str("type", dns.TypeToString[r.Question.Qtype]).
		Str("class", dns.ClassToString[r.Question.Qclass]).
		Dur("rtt", rtt).Err(err).Msg("request")

	return in.Answer, nil
}
