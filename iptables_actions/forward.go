package iptables_actions

import (
	"fmt"
	"strings"

	"github.com/mabels/steinstuecken/cmd/cli"
	"github.com/rs/zerolog"
	"k8s.io/kubernetes/pkg/util/iptables"
)

func addOrRemove(add_or_remove string, zlog *zerolog.Logger, ipChain iptables.Chain, params *stringArrayBuilder, ipt iptables.Interface) error {
	var err error
	switch add_or_remove {
	case "add":
		zlog.Debug().Str("chain", string(ipChain)).Str("params", strings.Join(params.out, " ")).Msg("adding rule")
		_, err = ipt.EnsureRule(iptables.Prepend, iptables.TableFilter, ipChain, params.out...)
	case "remove":
		zlog.Debug().Str("chain", string(ipChain)).Str("params", strings.Join(params.out, " ")).Msg("remove rule")
		err = ipt.DeleteRule(iptables.TableFilter, ipChain, params.out...)
	default:
		err = fmt.Errorf("unknown add_or_remove: %s", add_or_remove)
	}
	return err
}

func Forward(add_or_remove string, zlog *zerolog.Logger, ipChain iptables.Chain, ip string, target *cli.Target, ipt iptables.Interface) (errs []error) {
	inIfaceParam := []string{}
	if target.Interface.Input != nil {
		inIfaceParam = []string{"-i", *target.Interface.Input}
	}
	outIfaceParam := []string{}
	if target.Interface.Input != nil {
		outIfaceParam = []string{"-o", *target.Interface.Output}
	}

	for _, port := range target.Ports {
		proto := newStringArrayBuilder()
		if !(port.Proto == "" || port.Proto == "all") {
			proto.add("-p", port.Proto)
		}
		dport := newStringArrayBuilder()
		sport := newStringArrayBuilder()
		if len(port.Port) != 0 {
			if port.Proto != "icmp" {
				if len(port.Port) == 1 {
					dport.add("--dport", port.Port[0])
					sport.add("--sport", port.Port[0])
				} else {
					portStr := strings.Join(port.Port, ",")
					dport.add("-m", "multiport", "--dports", portStr)
					sport.add("-m", "multiport", "--sports", portStr)
				}
			} else {
				portStr := strings.Join(port.Port, ",")
				dport.add("--icmp-type", portStr)
				sport.add("--icmp-type", portStr)
			}
		}
		outStateful := newStringArrayBuilder()
		inStateful := newStringArrayBuilder()
		if target.NonStateful {
			outStateful.add("-m", "conntrack", "--ctstate", "RELATED,ESTABLISHED,NEW")
			inStateful.add("-m", "conntrack", "--ctstate", "RELATED,ESTABLISHED")
		}
		params := newStringArrayBuilder().
			add(outStateful.out...).
			add("-d", ip).
			add(proto.out...).
			add(dport.out...).
			add(outIfaceParam...).
			add("-j", "ACCEPT")
		err := addOrRemove(add_or_remove, zlog, ipChain, params, ipt)
		if err != nil {
			errs = append(errs, err)
			zlog.Error().Err(err).Msg("error ensuring rule")
			continue
		}
		params = newStringArrayBuilder().
			add(inStateful.out...).
			add("-s", ip).
			add(proto.out...).
			add(sport.out...).
			add(inIfaceParam...).
			add("-j", "ACCEPT")
		err = addOrRemove(add_or_remove, zlog, ipChain, params, ipt)
		if err != nil {
			errs = append(errs, err)
			zlog.Error().Err(err).Msg("error ensuring rule")
			continue
		}
	}
	return
}
