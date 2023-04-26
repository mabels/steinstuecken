package iptables_actions

import (
	"fmt"
	"strings"

	"github.com/mabels/steinstuecken/cmd/cli"
	"github.com/rs/zerolog"
	"k8s.io/kubernetes/pkg/util/iptables"
	"k8s.io/utils/exec"
)

type IpTableChain struct {
	Table     iptables.Table
	Chain     iptables.Chain
	BaseChain iptables.Chain
}

type IpTable struct {
	Protocol iptables.Protocol
	Execer   exec.Interface
	IpTable  iptables.Interface
	FWD      IpTableChain
	NAT      IpTableChain
}

type IpTables struct {
	IpV4 *IpTable
	IpV6 *IpTable
}

func initIPTable(zlog *zerolog.Logger, config *cli.Config, protocol iptables.Protocol) (*IpTable, error) {
	ret := IpTable{
		Execer:   exec.New(),
		Protocol: protocol,
		FWD: IpTableChain{
			Table:     iptables.TableFilter,
			Chain:     iptables.Chain("FWD-" + config.ChainName),
			BaseChain: iptables.ChainForward,
		},
		NAT: IpTableChain{
			Table:     iptables.TableNAT,
			Chain:     iptables.Chain("NAT-" + config.ChainName),
			BaseChain: iptables.ChainPostrouting,
		},
	}
	ret.IpTable = iptables.New(exec.New(), nil, protocol)
	table := ret.IpTable

	for _, tableChain := range []IpTableChain{ret.FWD, ret.NAT} {
		chain := tableChain.Chain
		chainStr := string(chain)
		_, err := table.EnsureChain(tableChain.Table, tableChain.BaseChain)
		if err != nil {
			zlog.Error().Err(err).Msg("error ensuring chain")
			return nil, err
		}
		err = table.DeleteRule(tableChain.Table, tableChain.BaseChain, "-j", chainStr)
		if err != nil && !strings.Contains(err.Error(), fmt.Sprintf("Chain '%s' does not exist", chainStr)) {
			zlog.Error().Err(err).Msg("error deleting rule")
			return nil, err
		}
		err = table.FlushChain(tableChain.Table, chain)
		if err != nil && !strings.Contains(err.Error(), fmt.Sprintf("error flushing chain \"%s\"", chainStr)) {
			zlog.Error().Err(err).Msg("error flushing chain")
			return nil, err
		}
		_, err = table.EnsureChain(tableChain.Table, chain)
		if err != nil {
			zlog.Error().Err(err).Msg("error ensuring chain")
			return nil, err
		}
		rulePosition := iptables.Append
		if config.FirstRule {
			rulePosition = iptables.Prepend
		}
		_, err = table.EnsureRule(rulePosition, tableChain.Table, tableChain.BaseChain, "-j", chainStr)
		if err != nil {
			zlog.Error().Str("chain", chainStr).Str("table", string(tableChain.Table)).Err(err).Msg("jump error ensuring rule")
			return nil, err
		}
		if !config.NoFinalDrop && tableChain.Table == iptables.TableFilter {
			_, err = table.EnsureRule(iptables.Append, tableChain.Table, chain, "-j", "DROP")
			if err != nil {
				zlog.Error().Str("chain", chainStr).Str("table", string(tableChain.Table)).Err(err).Msg("drop error ensuring rule")
				return nil, err
			}
		} else {
			_, err = table.EnsureRule(iptables.Append, tableChain.Table, chain, "-j", "RETURN")
			if err != nil {
				zlog.Error().Str("chain", chainStr).Str("table", string(tableChain.Table)).Err(err).Msg("return error ensuring rule")
				return nil, err
			}
		}
	}
	return &ret, nil
}

func InitIPTables(zlog *zerolog.Logger, config *cli.Config) (*IpTables, error) {
	ipv4Log := zlog.With().Str("ipversion", "v4").Logger()
	ipv4, err := initIPTable(&ipv4Log, config, iptables.ProtocolIpv4)
	if err != nil {
		return nil, err
	}
	ipv6Log := zlog.With().Str("ipversion", "v6").Logger()
	ipv6, err := initIPTable(&ipv6Log, config, iptables.ProtocolIpv6)
	if err != nil {
		return nil, err
	}
	return &IpTables{
		IpV4: ipv4,
		IpV6: ipv6,
	}, nil
}
