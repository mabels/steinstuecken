package main

import (
	// "context"
	// "fmt"

	"fmt"
	"net"
	"os"
	"path/filepath"
	"sync"

	"github.com/mabels/steinstuecken/cmd/cli"
	dnsEvents "github.com/mabels/steinstuecken/dns_event_stream"
	"github.com/mabels/steinstuecken/iptables_actions"
	"github.com/miekg/dns"
	"github.com/rs/zerolog"
	// "sigs.k8s.io/external-dns/provider/google"
	// "sigs.k8s.io/external-dns/provider"
	// "sigs.k8s.io/external-dns/endpoint"
	// sigs.k8s.io/external-dns/provider/aws"
)

func cidrInTxt(txts []string) *string {
	var ip *string = nil
	for _, txt := range txts {
		nip, _, err := net.ParseCIDR(txt)
		if err != nil {
			continue
		}
		if nip != nil {
			ip = &txt
			break
		}
	}
	return ip
}

func getIPAddress(rr dns.RR) (string, bool, error) {
	a, found := rr.(*dns.A)
	if found {
		ipA := a.A.String()
		return ipA, false, nil
	}
	aaaa, found := rr.(*dns.AAAA)
	if found {
		ipA := aaaa.AAAA.String()
		return ipA, false, nil
	}
	txt, found := rr.(*dns.TXT)
	if found {
		ip := cidrInTxt(txt.Txt)
		if ip == nil {
			return "", false, fmt.Errorf("found cidr in TXT record: %v", txt.Txt)
		}
		return *ip, false, nil
	}
	_, skip := rr.(*dns.CNAME)
	return "", skip, fmt.Errorf("error casting to dns.A/TXT")
}

type actionFn func(action string, zlog *zerolog.Logger, ipA string, target *cli.Target) []error

func selectIpTable(zlog *zerolog.Logger, ipts *iptables_actions.IpTables, target *cli.Target, subject dnsEvents.Subject, history []*dnsEvents.DnsResult) (actionFn, error) {
	var iptable *iptables_actions.IpTable
	switch subject.Key().Qtype {
	case dns.TypeA:
		iptable = ipts.IpV4
	case dns.TypeAAAA:
		iptable = ipts.IpV6
	case dns.TypeTXT:
		dnsResult := dnsEvents.NewestValidHistory(history)
		if len(dnsResult.Rrs) == 0 {
			err := fmt.Errorf("no TXT records found")
			zlog.Error().Err(err).Msg("LastValidHistor")
			return nil, err
		}
		for _, _rr := range dnsResult.Rrs {
			rr, found := _rr.(*dns.TXT)
			if !found {
				zlog.Warn().Str("_rr", _rr.String()).Msg("no dns.TXT")
				continue
			}
			ipStr := cidrInTxt(rr.Txt)
			if ipStr != nil {
				ip, _, err := net.ParseCIDR(*ipStr)
				if err != nil {
					zlog.Error().Err(err).Str("ipStr", *ipStr).Msg("no ip")
					continue
				}
				if ip == nil {
					zlog.Error().Str("ipStr", *ipStr).Msg("no ip")
					continue
				}
				if ip.To4() != nil {
					iptable = ipts.IpV4
				} else {
					iptable = ipts.IpV6
				}
				break
			} else {
				zlog.Warn().Strs("txt", rr.Txt).Msg("no ip")
			}
			if iptable != nil {
				break
			}
		}
		if iptable == nil {
			err := fmt.Errorf("no TXT records with valid IP found")
			zlog.Error().Err(err).Msg("no iptable found")
			return nil, err
		}
	default:
		err := fmt.Errorf("unknown qtype %d", subject.Key().Qtype)
		zlog.Error().Err(err).Uint16("qtype", subject.Key().Qtype).Msg("unknown qtype")
		return nil, err
	}
	if iptable == nil {
		zlog.Debug().Msg("skipping iptable")
		return func(add_remove string, alog *zerolog.Logger, ip string, target *cli.Target) []error {
			return []error{}
		}, nil
	}
	// var jump *iptables_actions.StringArrayBuilder
	actionFunc := func(add_remove string, alog *zerolog.Logger, ip string, target *cli.Target) []error {
		jump := iptables_actions.NewStringArrayBuilder().
			Add("-j", "ACCEPT").
			Add("-m", "comment", "--comment", dnsEvents.KeySubject(subject.Key()))
		return iptables_actions.Forward(add_remove, alog, iptable.FWD.Chain, iptable.FWD.Table, ip, target, iptable.IpTable, jump.Out)
	}
	forwardActionFunc := actionFunc
	if target.Snat4 != nil || target.Snat6 != nil {
		actionFunc = func(add_remove string, alog *zerolog.Logger, ip string, target *cli.Target) []error {
			ret := forwardActionFunc(add_remove, alog, ip, target)
			var snat *string
			if iptable.IpTable.IsIpv6() {
				snat = target.Snat6
			} else {
				snat = target.Snat4
			}
			if snat != nil {
				jump := iptables_actions.NewStringArrayBuilder().
					Add("-j", "SNAT", "--to-source", *snat).
					Add("-m", "comment", "--comment", dnsEvents.KeySubject(subject.Key()))
				ret = append(ret, iptables_actions.Forward(add_remove, alog, iptable.NAT.Chain, iptable.NAT.Table, ip, target, iptable.IpTable, jump.Out)...)
			}
			return ret
		}
	} else if target.Masq != nil {
		actionFunc = func(add_remove string, alog *zerolog.Logger, ip string, target *cli.Target) []error {
			ret := forwardActionFunc(add_remove, alog, ip, target)
			jump := iptables_actions.NewStringArrayBuilder().
				Add("-j", "MASQUERADE").
				Add("-m", "comment", "--comment", dnsEvents.KeySubject(subject.Key()))
			ret = append(ret, iptables_actions.Forward(add_remove, alog, iptable.NAT.Chain, iptable.NAT.Table, ip, target, iptable.IpTable, jump.Out)...)
			return ret
		}
	}
	return actionFunc, nil
}

func bindFn(zlog *zerolog.Logger, target *cli.Target, subject dnsEvents.Subject, ipts *iptables_actions.IpTables) func(history []*dnsEvents.DnsResult) {
	return func(history []*dnsEvents.DnsResult) {
		if history[0].Err != nil {
			zlog.Error().Err(history[0].Err).Msg("error resolving")
		} else {
			actionFunc, err := selectIpTable(zlog, ipts, target, subject, history)
			if err != nil {
				return
			}
			actions := dnsEvents.CurrentToActions(history)
			for _, action := range actions {
				errs := []error{}
				alog := zlog.With().Int("histories", len(history)).Str("action", action.Action).Str("subject", dnsEvents.KeySubject(subject.Key())).Logger()
				switch action.Action {
				case "newAdd":
					ipA, skip, err := getIPAddress(action.Current)
					if skip {
						continue
					}
					if err != nil {
						zlog.Error().Err(err).Msg("newAdd error")
						continue
					}
					errs = actionFunc("add", &alog, ipA, target)
				case "change":
					cipA, skip, err := getIPAddress(action.Current)
					if skip {
						continue
					}
					if err != nil {
						zlog.Error().Err(err).Msg("current change error")
						continue
					}
					pipA, skip, err := getIPAddress(action.Prev)
					if skip {
						continue
					}
					if err != nil {
						zlog.Error().Err(err).Msg("prev change error")
						continue
					}
					if cipA == pipA {
						continue
					}
					errs = append(errs, actionFunc("remove", &alog, pipA, target)...)
					errs = append(errs, actionFunc("add", &alog, cipA, target)...)
				case "oldDel":
					ipA, skip, err := getIPAddress(action.Prev)
					if skip {
						continue
					}
					if err != nil {
						zlog.Error().Err(err).Msg("prev oldDel error")
						continue
					}
					errs = actionFunc("remove", &alog, ipA, target)
				default:
					zlog.Fatal().Msg("unknown action")
				}
				if len(errs) > 0 {
					zlog.Log().Errs("errors", errs).Msg("errors in iptables")
				}
			}
		}
	}
}

type dstSrc struct {
	src string
	dst string
}

var templateIptableExecutables = []dstSrc{
	{src: "ip6tables-%s", dst: "ip6tables"},
	{src: "ip6tables-%s-restore", dst: "ip6tables-restore"},
	{src: "ip6tables-%s-save", dst: "ip6tables-save"},
	{src: "iptables-%s", dst: "iptables"},
	{src: "iptables-%s-restore", dst: "iptables-restore"},
	{src: "iptables-%s-save", dst: "iptables-save"},
}

func selectIpTablesExecutable(zlog *zerolog.Logger, config *cli.Config) error {
	if config.IpTablesType != "" {
		err := os.MkdirAll(config.AlternatePath, 0755)
		if err != nil {
			return err
		}
		err = os.Setenv("PATH", config.AlternatePath+":"+os.Getenv("PATH"))
		if err != nil {
			return err
		}
		switch config.IpTablesType {
		case "nft":
		case "legacy":
		default:
			return fmt.Errorf("unknown iptables type %s", config.IpTablesType)
		}
		for _, template := range templateIptableExecutables {
			srcFile := fmt.Sprintf(filepath.Join(config.SrcPath, template.src), config.IpTablesType)
			st, err := os.Stat(srcFile)
			if err != nil && !st.IsDir() && st.Mode().Perm()&0111 != 0 {
				return fmt.Errorf("src error stating %s: %w", srcFile, err)
			}
			dstFile := filepath.Join(config.AlternatePath, template.dst)
			_, err = os.Stat(dstFile)
			if config.AlternateForce {
				if err == nil {
					err = os.Remove(dstFile)
					if err != nil {
						return fmt.Errorf("error removing %s: %w", dstFile, err)
					}
				}
			} else if err == nil {
				return fmt.Errorf("dest should not exist %s", dstFile)
			}
			err = os.Symlink(srcFile, dstFile)
			if err != nil {
				return fmt.Errorf("error symlinking %s to %s: %w", srcFile, dstFile, err)
			}
		}
		zlog.Debug().Str("iptables_type", config.IpTablesType).Str("alternatepath", config.AlternatePath).Msg("setup alternate path")
	}
	return nil
}

func main() {
	zlog := zerolog.New(os.Stderr).With().Timestamp().Logger()
	config, errs := cli.GetConfig(&zlog)
	if len(errs) > 0 {
		zlog.Fatal().Errs("errors", errs).Msg("errors in config")
	}

	err := selectIpTablesExecutable(&zlog, &config)
	if err != nil {
		zlog.Fatal().Err(err).Msg("error selecting iptables")
	}

	ipts, err := iptables_actions.InitIPTables(&zlog, &config)
	if err != nil {
		zlog.Fatal().Err(err).Msg("error initializing iptables")
	}

	des := dnsEvents.NewDnsEventStream(&zlog)
	defer des.Stop()
	des.Start()
	for _, _target := range config.Targets {
		target := _target
		for _, subject := range target.Subjects {

			as, err := des.CreateSubject(subject)
			if err != nil {
				zlog.Error().Err(err).Msg("error creating subject")
				continue
			}
			as.Bind(bindFn(as.Log, &target, subject, ipts))
			err = as.Activate()
			if err != nil {
				zlog.Error().Err(err).Msg("error activating subject")
				continue
			}
			as.Log.Info().Str("target", dnsEvents.KeySubject(as.Subject.Key())).Msg("activated")
		}
	}
	wg := sync.WaitGroup{}
	wg.Add(1)
	wg.Wait()
}
