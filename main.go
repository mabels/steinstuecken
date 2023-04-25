package main

import (
	// "context"
	// "fmt"

	"fmt"
	"net"
	"os"
	"strings"
	"sync"

	"github.com/mabels/steinstuecken/cmd/cli"
	dnsEvents "github.com/mabels/steinstuecken/dns_event_stream"
	"github.com/mabels/steinstuecken/iptables_actions"
	"github.com/miekg/dns"
	"github.com/rs/zerolog"
	"k8s.io/kubernetes/pkg/util/iptables"
	"k8s.io/utils/exec"
	// "sigs.k8s.io/external-dns/provider/google"
	// "sigs.k8s.io/external-dns/provider"
	// "sigs.k8s.io/external-dns/endpoint"
	// sigs.k8s.io/external-dns/provider/aws"
)

func getIPAddress(rr dns.RR) (string, error) {
	a, found := rr.(*dns.A)
	if !found {
		txt, found := rr.(*dns.TXT)
		if !found {
			return "", fmt.Errorf("error casting to dns.A/TXT")
		}
		return txt.Txt[0], nil
	}
	ipA := net.IPv4(a.A[0], a.A[1], a.A[2], a.A[3]).String()
	return ipA, nil
}

func main() {
	zlog := zerolog.New(os.Stderr).With().Timestamp().Logger()
	config, errs := cli.GetConfig(&zlog)
	if len(errs) > 0 {
		zlog.Fatal().Errs("errors", errs).Msg("errors in config")
	}

	execer := exec.New()
	protocolv4 := iptables.ProtocolIpv4
	protocolv6 := iptables.ProtocolIpv6
	ipt4 := iptables.New(execer, nil, protocolv4)
	ipt6 := iptables.New(execer, nil, protocolv6)

	ipChain := iptables.Chain(config.ChainName)
	for _, table := range []iptables.Interface{ipt4, ipt6} {
		_, err := table.EnsureChain(iptables.TableFilter, iptables.ChainForward)
		if err != nil {
			zlog.Error().Err(err).Msg("error ensuring chain")
			return
		}
		err = table.DeleteRule(iptables.TableFilter, iptables.ChainForward, "-j", config.ChainName)
		if err != nil && !strings.Contains(err.Error(), fmt.Sprintf("Chain '%s' does not exist", config.ChainName)) {
			zlog.Error().Err(err).Msg("error deleting rule")
			return
		}
		err = table.FlushChain(iptables.TableFilter, ipChain)
		if err != nil && !strings.Contains(err.Error(), fmt.Sprintf("error flushing chain \"%s\"", config.ChainName)) {
			zlog.Error().Err(err).Msg("error flushing chain")
			return
		}
		_, err = table.EnsureChain(iptables.TableFilter, ipChain)
		if err != nil {
			zlog.Error().Err(err).Msg("error ensuring chain")
			return
		}
		rulePosition := iptables.Append
		if config.FirstRule {
			rulePosition = iptables.Prepend
		}
		_, err = table.EnsureRule(rulePosition, iptables.TableFilter, iptables.ChainForward, "-j", config.ChainName)
		if err != nil {
			zlog.Error().Err(err).Msg("error ensuring rule")
			return
		}
		if !config.NoFinalDrop {
			_, err = table.EnsureRule(iptables.Append, iptables.TableFilter, ipChain, "-j", "DROP")
			if err != nil {
				zlog.Error().Err(err).Msg("error ensuring rule")
				return
			}
		} else {
			_, err = table.EnsureRule(iptables.Append, iptables.TableFilter, ipChain, "-j", "RETURN")
			if err != nil {
				zlog.Error().Err(err).Msg("error ensuring rule")
				return
			}
		}
	}

	des := dnsEvents.NewDnsEventStream(&zlog)
	defer des.Stop()
	des.Start()
	for _, _target := range config.Targets {
		target := _target
		as, err := des.CreateSubject(target.Subject)
		if err != nil {
			zlog.Fatal().Err(err).Msg("error creating subject")
			continue
		}
		as.Bind(func(history []*dnsEvents.DnsResult) {
			if history[0].Err != nil {
				zlog.Error().Err(history[0].Err).Msg("error resolving")
			} else {
				actions := dnsEvents.CurrentToActions(history)
				for _, action := range actions {
					var errs []error
					alog := zlog.With().Int("histories", len(history)).Str("action", action.Action).Str("subject", dnsEvents.KeySubject(target.Subject.Key())).Logger()
					switch action.Action {
					case "newAdd":
						ipA, err := getIPAddress(action.Current)
						if err != nil {
							zlog.Error().Err(err).Msg("newAdd error")
							break
						}
						errs = iptables_actions.Forward("add", &alog, ipChain, ipA, &target, ipt4)
					case "change":
						cipA, err := getIPAddress(action.Current)
						if err != nil {
							zlog.Error().Err(err).Msg("current change error")
							break
						}
						pipA, err := getIPAddress(action.Prev)
						if err != nil {
							zlog.Error().Err(err).Msg("prev change error")
							break
						}
						if cipA == pipA {
							continue
						}
						errs = append(errs, iptables_actions.Forward("remove", &alog, ipChain, pipA, &target, ipt4)...)
						errs = append(errs, iptables_actions.Forward("add", &alog, ipChain, cipA, &target, ipt4)...)
					case "oldDel":
						ipA, err := getIPAddress(action.Prev)
						if err != nil {
							zlog.Error().Err(err).Msg("prev oldDel error")
							break
						}
						errs = iptables_actions.Forward("remove", &alog, ipChain, ipA, &target, ipt4)
					default:
						zlog.Fatal().Msg("unknown action")
					}
					if len(errs) > 0 {
						zlog.Log().Errs("errors", errs).Msg("errors in iptables")
					}
				}
			}
		})
		err = as.Activate()
		if err != nil {
			zlog.Fatal().Err(err).Msg("error activating subject")
		}
		zlog.Info().Str("target", dnsEvents.KeySubject(as.Subject.Key())).Msg("activated")
	}

	wg := sync.WaitGroup{}
	wg.Add(1)
	wg.Wait()

	// dns, err := google.NewGoogleProvider(context.Background(),
	// 	"vibrant-mantis-723",
	// 	endpoint.DomainFilter{Filters:[]string{"adviser.com"}},
	// 	provider.ZoneIDFilter{ZoneIDs:[]string{}},
	// 	0, 0, "", false)
	// if err != nil {
	// 	panic(err)
	// }

	// eps, err := dns.Records(context.Background())
	// if err != nil {
	// 	panic(err)
	// }
	// for _, ep := range eps {
	// 	fmt.Println(ep)
	// }
	// err = dns.CreateRecords([]*endpoint.Endpoint{
	// 	endpoint.NewEndpoint("steinstuecken.adviser.com.", "AAAA", "fc00::1", "fc00::2"),
	// })
	// if err != nil {
	// 	panic(err)
	// }

	// dns, err := dns_observer.NewDNSObserver(dns_observer.Direct, "www.adviser.com", []string{"AAAA", "A"})
}
