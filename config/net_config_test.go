package config

import (
	"strings"
	"testing"
)

func TestNewNetConfigEmpty(t *testing.T) {
	_, err := NewNetConfigFromYaml([]byte(""))
	if err == nil {
		t.Errorf("error: %v", err)
	}
}

func trimLines(in string) (out string) {
	lines := strings.Split(in, "\n")
	firstIndent := -1
	for line, str := range lines {
		if firstIndent == -1 && strings.TrimSpace(str) == "" {
			continue
		}
		if firstIndent == -1 {
			firstIndent = len(str) - len(strings.TrimLeft(str, " \t"))
		}
		if len(str) > firstIndent {
			lines[line] = str[firstIndent:]
		} else {
			lines[line] = ""
		}
	}
	out = strings.Join(lines, "\n")
	return out
}

func TestNewNetConfigMinimal(t *testing.T) {
	nc, err := NewNetConfigFromYaml([]byte(trimLines(`
        netConfig:
            baseDomain: example.com
            dnsProvider: google
            description: "Example.com"
    `)))
	if err != nil {
		t.Errorf("error: %v", err)
	}
	if nc.BaseDomain != "example.com" {
		t.Errorf("baseDomain: %v", nc.BaseDomain)
	}
	if nc.DNSProvider != "google" {
		t.Errorf("dnsProvider: %v", nc.DNSProvider)
	}
	if nc.Description != "Example.com" {
		t.Errorf("description: %v", nc.Description)
	}
	if nc.DNSResolver.Protocol != DNSProtocolSYS {
		t.Errorf("dnsResolver.protocol: %v", nc.DNSResolver.Protocol)
	}
	if len(nc.DNSResolver.Servers) != 0 {
		t.Errorf("dnsResolver.servers: %v", nc.DNSResolver.Servers)
	}
	if len(nc.Hops) != 0 {
		t.Errorf("hops: %v", nc.Hops)
	}
	if len(nc.HopChains) != 0 {
		t.Errorf("hops: %v", nc.Hops)
	}
	if len(nc.Endpoints) != 0 {
		t.Errorf("endpoint: %v", nc.Endpoints)
	}
}

func TestNewNetConfigHops(t *testing.T) {
	nc, err := NewNetConfigFromYaml([]byte(trimLines(`
        netConfig:
            baseDomain: example.com
            dnsProvider: google
            description: "Example.com"
            dnsResolver:
                protocol: udp
                servers:
                    - 8.8.8.8
                    - 8.8.4.4
            hops:
                Entrypoint:
                    role: entrypoint
                    dnsResolver:
                        protocol: udp
                        servers:
                            - 1.1.1.1
                Fanout:
                    role: fanout
                    listen:
                        protocol: http3
                        key: /etc/letsencrypt/live/example.com/privkey.pem
                        cert: /etc/letsencrypt/live/example.com/fullchain.pem
                        local:
                            name: 0.0.0.0
                            port: 4711
                        externals:
                            - name: example.com
                              port: 4711
    `)))
	if err != nil {
		t.Errorf("error: %v", err)
	}
	if len(nc.Hops) != 2 {
		t.Errorf("hops: %v", nc.Hops)
	}
	if nc.Hops["Entrypoint"].Name != "Entrypoint" {
		t.Errorf("hops[Entrypoint].Name: %v", nc.Hops["Entrypoint"].Name)
	}
	if nc.Hops["Entrypoint"].DNSResolver.Protocol != DNSProtocolUDP {
		t.Errorf("hops[Entrypoint].DNSResolver.Protocol: %v", nc.Hops["Fanout"].DNSResolver.Protocol)
	}
	if len(nc.Hops["Entrypoint"].DNSResolver.Servers) != 1 {
		t.Errorf("hops[Entrypoint].DNSResolver.Servers: %v", nc.Hops["Entrypoint"].DNSResolver.Servers)
	}
	if nc.Hops["Entrypoint"].DNSResolver.Servers[0] != "1.1.1.1" {
		t.Errorf("hops[Entrypoint].DNSResolver.Servers[0]: %v", nc.Hops["Entrypoint"].DNSResolver.Servers[0])
	}
	if nc.Hops["Entrypoint"].Role != EntryPoint {
		t.Errorf("hops[Entrypoint].Role: %v", nc.Hops["Entrypoint"].Role)
	}
	if nc.Hops["Fanout"].DNSResolver.Protocol != DNSProtocolSYS {
		t.Errorf("hops[Fanout].DNSResolver.Protocol: %v", nc.Hops["Fanout"].DNSResolver.Protocol)
	}
	if nc.Hops["Fanout"].Name != "Fanout" {
		t.Errorf("hops[Fanout].Name: %v", nc.Hops["Fanout"].Name)
	}
	if nc.Hops["Fanout"].Role != Fanout {
		t.Errorf("hops[Fanout].Role: %v", nc.Hops["Fanout"].Role)
	}
	if nc.Hops["Fanout"].Listen.Protocol != HTTP3 {
		t.Errorf("hops[Fanout].Listen.Protocol: %v", nc.Hops["Fanout"].Listen.Protocol)
	}
	if nc.Hops["Fanout"].Listen.Key != "/etc/letsencrypt/live/example.com/privkey.pem" {
		t.Errorf("hops[Fanout].Listen.Key: %v", nc.Hops["Fanout"].Listen.Key)
	}
	if nc.Hops["Fanout"].Listen.Cert != "/etc/letsencrypt/live/example.com/fullchain.pem" {
		t.Errorf("hops[Fanout].Listen.Cert: %v", nc.Hops["Fanout"].Listen.Cert)
	}
	if nc.Hops["Fanout"].Listen.Local.Name != "0.0.0.0" {
		t.Errorf("hops[Fanout].Listen.Local.Name: %v", nc.Hops["Fanout"].Listen.Local.Name)
	}
	if nc.Hops["Fanout"].Listen.Local.Port != 4711 {
		t.Errorf("hops[Fanout].Listen.Local.Port: %v", nc.Hops["Fanout"].Listen.Local.Port)
	}

	if len(nc.Hops["Fanout"].Listen.Externals) != 1 {
		t.Errorf("hops[Fanout].Listen.Externals: %v", nc.Hops["Fanout"].Listen.Externals)
	}
	if nc.Hops["Fanout"].Listen.Externals[0].Name != "example.com" {
		t.Errorf("hops[Fanout].Listen.External.Name: %v", nc.Hops["Fanout"].Listen.Externals[0].Name)
	}
	if nc.Hops["Fanout"].Listen.Externals[0].Port != 4711 {
		t.Errorf("hops[Fanout].Listen.External.Port: %v", nc.Hops["Fanout"].Listen.Externals[0].Port)
	}

}

func TestNewNetConfigHopChainsDefect(t *testing.T) {
	_, err := NewNetConfigFromYaml([]byte(trimLines(`
        netConfig:
            baseDomain: example.com
            dnsProvider: google
            description: "Example.com"
            hops:
                MyEntrypoint:
                    role: entrypoint
                MyFanout:
                    role: fanout
                    listen:
                        protocol: http3
                        key: /etc/letsencrypt/live/example.com/privkey.pem
                        cert: /etc/letsencrypt/live/example.com/fullchain.pem
                        local:
                            name: 0.0.0.0
                            port: 4711
                        externals:
                            - name: example.com
                              port: 4711
            hopChains:
              "standard outbound":
                  hops:
                    - MyEntrypoint
                    - MyFanout
                    - kaputt
    `)))
	if err == nil {
		t.Errorf("There should be an error")
	}
	if err.Error() != "hop kaputt not found" {
		t.Errorf("error: %v", err)
	}
}

func TestNewNetConfigHopChains(t *testing.T) {
	_, err := NewNetConfigFromYaml([]byte(trimLines(`
        netConfig:
            baseDomain: example.com
            dnsProvider: google
            description: "Example.com"
            hops:
                MyEntrypoint:
                    role: entrypoint
                MyFanout:
                    role: fanout
                    listen:
                        protocol: http3
                        key: /etc/letsencrypt/live/example.com/privkey.pem
                        cert: /etc/letsencrypt/live/example.com/fullchain.pem
                        local:
                            name: 0.0.0.0
                            port: 4711
                        externals:
                            - name: example.com
                              port: 4711
            hopChains:
              "standard outbound":
                  hops:
                    - MyEntrypoint
                    - MyFanout
    `)))
	if err != nil {
		t.Errorf("There should be an error")
	}
}

func TestNewNetConfigHopChainsResolveKey(t *testing.T) {
	nc, err := NewNetConfigFromYaml([]byte(trimLines(`
        netConfig:
            baseDomain: example.com
            dnsProvider: google
            description: "Example.com"
            hops:
                MyEntrypoint:
                    role: entrypoint
                MyFanout:
                    role: fanout
                    listen:
                        protocol: http3
                        key: file://./net_config_test.go
                        cert: file://./net_config_test.go
                        local:
                            name: 0.0.0.0
                            port: 4711
                        externals:
                            - name: example.com
                              port: 4711
            hopChains:
              "standard outbound":
                  hops:
                    - MyEntrypoint
                    - MyFanout
    `)), &KeyFileResolver{})
	if err != nil {
		t.Errorf("There should be an error:%v", err)
	}
	if !strings.Contains(nc.Hops["MyFanout"].Listen.Key, "key: file://./netconfig_test.go") {
		t.Errorf("hops[Fanout].Listen.Key: %v", nc.Hops["MyFanout"].Listen.Key)
	}
	if !strings.Contains(nc.Hops["MyFanout"].Listen.Cert, "cert: file://./netconfig_test.go") {
		t.Errorf("hops[Fanout].Listen.Key: %v", nc.Hops["MyFanout"].Listen.Cert)
	}
}
