package iptables_actions

import (
	"fmt"
	"strings"

	"github.com/mabels/steinstuecken/cmd/cli"
	"github.com/rs/zerolog"
	"k8s.io/kubernetes/pkg/util/iptables"
)

func addOrRemove(add_or_remove string, zlog *zerolog.Logger, ipChain iptables.Chain, ipTable iptables.Table, params *StringArrayBuilder, ipt iptables.Interface) error {
	var err error
	switch add_or_remove {
	case "add":
		zlog.Debug().Str("chain", string(ipChain)).Str("params", strings.Join(params.Out, " ")).Msg("adding rule")
		_, err = ipt.EnsureRule(iptables.Prepend, ipTable, ipChain, params.Out...)
	case "remove":
		zlog.Debug().Str("chain", string(ipChain)).Str("params", strings.Join(params.Out, " ")).Msg("remove rule")
		err = ipt.DeleteRule(ipTable, ipChain, params.Out...)
	default:
		err = fmt.Errorf("unknown add_or_remove: %s", add_or_remove)
	}
	return err
}

func Forward(add_or_remove string, zlog *zerolog.Logger, ipChain iptables.Chain, ipTable iptables.Table, ip string, target *cli.Target, ipt iptables.Interface, jump []string) (errs []error) {
	inIfaceParam := []string{}
	if target.Interface.Input != nil {
		inIfaceParam = []string{"-i", *target.Interface.Input}
	}
	outIfaceParam := []string{}
	if target.Interface.Input != nil {
		outIfaceParam = []string{"-o", *target.Interface.Output}
	}

	for _, port := range target.Ports {
		proto := NewStringArrayBuilder()
		if !(port.Proto == "" || port.Proto == "all") {
			proto.Add("-p", port.Proto)
		}
		dport := NewStringArrayBuilder()
		sport := NewStringArrayBuilder()
		if len(port.Port) != 0 {
			if port.Proto != "icmp" {
				if len(port.Port) == 1 {
					dport.Add("--dport", port.Port[0])
					sport.Add("--sport", port.Port[0])
				} else {
					portStr := strings.Join(port.Port, ",")
					dport.Add("-m", "multiport", "--dports", portStr)
					sport.Add("-m", "multiport", "--sports", portStr)
				}
			} else {
				portStr := strings.Join(port.Port, ",")
				dport.Add("--icmp-type", portStr)
				sport.Add("--icmp-type", portStr)
			}
		}
		outStateful := NewStringArrayBuilder()
		inStateful := NewStringArrayBuilder()
		if target.NonStateful {
			outStateful.Add("-m", "conntrack", "--ctstate", "RELATED,ESTABLISHED,NEW")
			inStateful.Add("-m", "conntrack", "--ctstate", "RELATED,ESTABLISHED")
		}
		params := NewStringArrayBuilder().
			Add(outStateful.Out...).
			Add("-d", ip).
			Add(proto.Out...).
			Add(dport.Out...).
			Add(outIfaceParam...).
			Add(jump...)
		err := addOrRemove(add_or_remove, zlog, ipChain, ipTable, params, ipt)
		if err != nil {
			errs = append(errs, err)
			zlog.Error().Str("add_or_remove", add_or_remove).Str("chain", string(ipChain)).Err(err).Msg("out error ensuring rule")
			continue
		}
		if ipTable != iptables.TableNAT {
			params = NewStringArrayBuilder().
				Add(inStateful.Out...).
				Add("-s", ip).
				Add(proto.Out...).
				Add(sport.Out...).
				Add(inIfaceParam...).
				Add(jump...)
			err = addOrRemove(add_or_remove, zlog, ipChain, ipTable, params, ipt)
			if err != nil {
				errs = append(errs, err)
				zlog.Error().Str("add_or_remove", add_or_remove).Str("chain", string(ipChain)).Err(err).Msg("in error ensuring rule")
				continue
			}
		}
	}
	return
}
