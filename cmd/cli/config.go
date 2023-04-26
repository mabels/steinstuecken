package cli

import (
	"fmt"
	"math"
	"net"
	"net/url"
	"regexp"
	"strconv"
	"strings"

	des "github.com/mabels/steinstuecken/dns_event_stream"
	"github.com/miekg/dns"
	"github.com/rs/zerolog"
	"github.com/spf13/pflag"
)

type Port struct {
	Port  []string
	Proto string
}

type Target struct {
	Subjects    []des.Subject
	Ports       []Port
	NonStateful bool
	Interface   struct {
		Input  *string
		Output *string
	}
	Protos  []string
	Snat4   *string
	Snat6   *string
	Masq    *string
	Forward *string
}

type Config struct {
	// ForwardMode bool
	// MasqMode    bool
	// SNatMode    bool
	ChainName   string
	NoFinalDrop bool
	FirstRule   bool
	targetsStr  []string // sken://target[:port]/?type=A&nameserver=IP&snat=IP&masq[=oif]&forward
	Targets     []Target
}

type Cidr struct {
	Hdr    dns.RR_Header
	IP     net.IP
	Prefix int
}

func (c *Cidr) String() string {
	return fmt.Sprintf("%s/%d", c.IP, c.Prefix)
}

func (c *Cidr) Header() *dns.RR_Header {
	return &c.Hdr
}

// func (c *Cidr) copy() dns.RR {
// 	return c
// 	// return 1
// }

var rePorts = regexp.MustCompile("[|,]+")
var rePrefixUrl = regexp.MustCompile(`/\d+$`)

func getSubjects(targetUrl *url.URL, log *zerolog.Logger) ([]des.Subject, error) {
	var subjects []des.Subject
	if net.ParseIP(targetUrl.Hostname()) != nil {
		ip := net.ParseIP(targetUrl.Hostname())
		rrType := dns.TypeA
		if ip.To4() == nil {
			rrType = dns.TypeAAAA
		}
		rrHeader := dns.RR_Header{
			Name:     targetUrl.Hostname(),
			Rrtype:   rrType,
			Ttl:      math.MaxInt32,
			Class:    dns.ClassINET,
			Rdlength: uint16(len(ip)),
		}
		txt := ip.String()
		prefixStr := targetUrl.Path
		if rePrefixUrl.MatchString(prefixStr) {
			prefix, err := strconv.Atoi(strings.TrimLeft(prefixStr, "/"))
			if !(err == nil && ((ip.To4() == nil && prefix >= 0 && prefix <= 128) ||
				(ip.To4() != nil && prefix >= 0 && prefix <= 32))) {
				prefix = 32
				if ip.To4() == nil {
					prefix = 128
				}
			}
			txt = fmt.Sprintf("%s/%d", txt, prefix)
		}
		rr := &dns.TXT{
			Hdr: rrHeader,
			Txt: []string{txt},
		}
		subjects = append(subjects, &des.FixResolverSubject{
			Question: dns.Question{
				Name:   targetUrl.Hostname(),
				Qtype:  dns.TypeTXT,
				Qclass: dns.ClassINET,
			},
			Result: []dns.RR{rr},
		})
	} else {
		hostname := targetUrl.Hostname()
		if !strings.HasSuffix(hostname, ".") {
			hostname += "." // dns package requires trailing dot
		}
		strTypes, found := targetUrl.Query()["type"]
		if !found {
			strTypes = []string{"A"}
		}
		types := []uint16{}
		for _, strType := range strTypes {
			typ, found := dns.StringToType[strType]
			if !found {
				continue
			}
			types = append(types, typ)
		}
		for _, typ := range types {
			sysresolver := des.SysResolverSubject{
				Log:         log,
				NameServers: targetUrl.Query()["nameserver"],
				Question: dns.Question{
					Name:   hostname,
					Qclass: dns.ClassINET,
					Qtype:  typ,
				},
			}
			subjects = append(subjects, &sysresolver)
		}
	}
	return subjects, nil
}

func GetConfig(log *zerolog.Logger) (Config, []error) {
	conf := Config{}
	pflag.StringVar(&conf.ChainName, "chain-name", "STEINSTUECKEN", "iptables chain name")
	pflag.BoolVar(&conf.NoFinalDrop, "no-final-drop", false, "do not drop packets that do not match any rule")
	pflag.BoolVar(&conf.FirstRule, "first-rule", false, "insert rule as first rule in chain")
	pflag.StringArrayVar(&conf.targetsStr, "target", []string{}, "target to connect to")
	pflag.Parse()
	errs := []error{}
	for _, targetStr := range conf.targetsStr {
		targetUrl, err := url.Parse(targetStr)
		if err != nil {
			errs = append(errs, fmt.Errorf("target %s is not a valid url: %v", targetStr, err))
			continue
		}
		if targetUrl.Scheme != "sken" {
			errs = append(errs, fmt.Errorf("target %s has invalid scheme: %v", targetStr, err))
			continue
		}
		subjects, err := getSubjects(targetUrl, log)
		if err != nil {
			errs = append(errs, err)
			continue
		}
		ports := []Port{}
		portsStrs, found := targetUrl.Query()["port"]
		if !found {
			ports = append(ports, Port{Port: []string{"443"}, Proto: "tcp"})
		} else {
			for _, portsStr := range portsStrs {
				splittedPorts := strings.Split(portsStr, "/")
				if len(splittedPorts) >= 1 {
					// port, err := strconv.Atoi(splittedPorts[0])
					// if err != nil {
					// 	errs = append(errs, fmt.Errorf("target %s has invalid port: %v", targetStr, err))
					// 	continue
					// }
					proto := "tcp"
					if len(splittedPorts) >= 2 {
						proto = splittedPorts[1]
					}
					ports = append(ports, Port{Port: rePorts.Split(splittedPorts[0], -1), Proto: proto})
				} else {
					errs = append(errs, fmt.Errorf("target %s has invalid port: %v", targetStr, err))
					continue
				}
			}
		}
		iface := struct {
			Input  *string
			Output *string
		}{}
		inIfaceStr, found := targetUrl.Query()["inIface"]
		if found {
			iface.Input = &inIfaceStr[0]
		}
		outIfaceStr, found := targetUrl.Query()["outIface"]
		if found {
			iface.Output = &outIfaceStr[0]
		}

		_, nonStateful := targetUrl.Query()["nonStateful"]

		target := Target{
			Ports:       ports,
			Subjects:    subjects,
			Interface:   iface,
			NonStateful: nonStateful,
		}

		target.Forward = &targetUrl.Host

		snat4, snat4found := targetUrl.Query()["snat4"]
		snat6, snat6found := targetUrl.Query()["snat6"]
		_, masqfound := targetUrl.Query()["masq"]

		if (snat4found || snat6found) && !masqfound {
			if len(snat4) > 0 {
				target.Snat4 = &snat4[0]
			}
			if len(snat6) > 0 {
				target.Snat6 = &snat6[0]
			}
		} else if !(snat4found || snat6found) && masqfound {
			target.Masq = &targetUrl.Host
		} else if (snat4found || snat6found) && masqfound {
			errs = append(errs, fmt.Errorf("target %s only one mode is allowed snat/masq", targetStr))
			continue
		}

		conf.Targets = append(conf.Targets, target)

	}
	return conf, errs
}
