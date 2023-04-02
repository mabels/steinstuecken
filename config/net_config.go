package config

import (
	"fmt"
	"os"
	"strings"

	"gopkg.in/yaml.v3"
)

type HopRole string

const (
	EntryPoint  HopRole = "entrypoint"  // The first hop in the chain
	EntryFanout HopRole = "entryfanout" // The first hop in the chain that forwards directly
	Relay       HopRole = "Relay"       // A hop that Relays to a Relay or a Fanout
	Fanout      HopRole = "fanout"      // A hop that forwards to multiple other hops
)

type HopProtocol string

const (
	HTTP3 HopProtocol = "http3"
	HTTPS HopProtocol = "https"
)

type Address struct {
	Name string `yaml:"name"` // IPAddress or DNSName
	Port int    `yaml:"port"`
}

type HopListen struct {
	Protocol  HopProtocol `yaml:"protocol"`
	Key       string      `yaml:"key"`  // pem or secretRef:keyName
	Cert      string      `yaml:"cert"` // pem or secretRef:keyName
	Local     Address     `yaml:"local"`
	Externals []Address   `yaml:"externals"`
}

type Hop struct {
	Role        HopRole     `yaml:"role"`
	Name        string      `yaml:"name"`
	Listen      HopListen   `yaml:"listen"`
	DNSResolver DNSResolver `yaml:"dnsResolver"`
}

// type ListenHop struct {
// 	Hop
// 	ListenUrl   string `yaml:"listen"`   // https://0.0.0.0:4711 or http3://0.0.0.0:4711
// 	ExternalUrl string `yaml:"external"` // https://example.com" or http3://example.com
// }

type FlatHopChains struct {
	Name string   `yaml:"name"`
	Hops []string `yaml:"hops"` // reference hops by name
}

type HopChains struct {
	Name string `yaml:"name"`
	Hops []*Hop `yaml:"hops"` // reference hops by name
}

type EndpointConfig struct {
	Name        string  `yaml:"endpoint"`
	Description string  `yaml:"description"`
	HopChain    string  `yaml:"hopChain"`
	TargetUrl   string  `yaml:"target"`
	FingerPrint *string `yaml:"thumbNail"`
}

type FlatNetConfig struct {
	BaseDomain  string `yaml:"baseDomain"`
	DNSProvider string `yaml:"dnsProvider"`
	Description string `yaml:"description,omitempty"`
	DNSResolver DNSResolver
	Hops        map[string]Hop            `yaml:"hops,omitempty"`
	HopChains   map[string]FlatHopChains  `yaml:"hopChains,omitempty"`
	Endpoints   map[string]EndpointConfig `yaml:"endpoints,omitempty"`
}

type DNSProtocol string

const (
	DNSProtocolSYS  DNSProtocol = "sys"
	DNSProtocolUDP  DNSProtocol = "udp"
	DNSProtocolTCP  DNSProtocol = "tcp"
	DNSProtocolDOH  DNSProtocol = "doh"
	DNSProtocolQUIC DNSProtocol = "quic"
)

type DNSResolver struct {
	Protocol DNSProtocol
	Servers  []string
}

type NetConfig struct {
	BaseDomain  string `yaml:"baseDomain"`
	DNSProvider string `yaml:"dnsProvider"`
	DNSResolver DNSResolver
	Description string                    `yaml:"description,omitempty"`
	Hops        map[string]Hop            `yaml:"hops,omitempty"`
	HopChains   map[string]HopChains      `yaml:"hopChains,omitempty"`
	Endpoints   map[string]EndpointConfig `yaml:"endpoints,omitempty"`
}

/*


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
    entrypoint:
        role: entrypoint
        dnsResolver:
            protocol: udp
            servers:
                - 8.8.8.8
                - 8.8.4.4
    fanout:
        role: fanout
        listen:
            protocol: http3
            key: /etc/letsencrypt/live/example.com/privkey.pem
            cert: /etc/letsencrypt/live/example.com/fullchain.pem
            local:
                name: 0.0.0.0
                port: 4711
            external:
                name: example.com
                port: 4711
  hopChains:
  - name: "standard outbound"
    hops:
    - entrypoint
    - fanout

*/

func fixHops(hops map[string]Hop, dr *DNSResolver) error {
	for name, hop := range hops {
		hop.Name = name
		fixDNSResolver(&hop.DNSResolver, dr)
		switch hop.Role {
		case EntryPoint:
		case EntryFanout:
		case Relay:
		case Fanout:
		default:
			return fmt.Errorf("hop %s has invalid role %s", name, hop.Role)
		}
		hops[name] = hop
	}
	return nil
}

func fixHopChains(netConfig *FlatNetConfig) error {
	for name, hopChain := range netConfig.HopChains {
		hopChain.Name = name
		if len(hopChain.Hops) == 0 {
			return fmt.Errorf("hopChain %s has no hops", name)
		}
		for i, hopRef := range hopChain.Hops {
			hop, found := netConfig.Hops[hopRef]
			if !found {
				return fmt.Errorf("hop %s not found", hopRef)
			}
			if i == 0 {
				switch hop.Role {
				case EntryPoint:
					if len(hopChain.Hops) == 1 {
						return fmt.Errorf("hop chain(%s) with entrypoint must more entries", hopChain.Name)
					}
				case EntryFanout:
					if len(hopChain.Hops) != 1 {
						return fmt.Errorf("hop chain(%s) with entryfanout must have only one entry", hopChain.Name)
					}
				default:
					return fmt.Errorf("hop chain(%s) must start with entrypoint", hopChain.Name)
				}
			} else if hop.Role == EntryPoint || hop.Role == EntryFanout {
				return fmt.Errorf("hop chain(%s) entrypoint/entryfanout(%s) only possible on start of hopchain", hopChain.Name, hop.Name)
			}
		}
		netConfig.HopChains[name] = hopChain
	}
	return nil
}

func flatToNetConfig(fnc *FlatNetConfig, nc *NetConfig) error {
	nc.BaseDomain = fnc.BaseDomain
	nc.DNSProvider = fnc.DNSProvider
	nc.Description = fnc.Description
	nc.DNSResolver = fnc.DNSResolver
	nc.Hops = fnc.Hops
	nc.HopChains = make(map[string]HopChains)
	for name, hopChain := range fnc.HopChains {
		hc := HopChains{
			Name: name,
			Hops: make([]*Hop, len(hopChain.Hops)),
		}
		for i, hopRef := range hopChain.Hops {
			hop, found := fnc.Hops[hopRef]
			if !found {
				return fmt.Errorf("hop %s not found", hop.Name)
			}
			hc.Hops[i] = &hop
		}
		nc.HopChains[name] = hc
	}
	nc.Endpoints = fnc.Endpoints
	return nil
}

type KeyResolver interface {
	Resolve(name string) (key string, err error)
}

type KeyFileResolver struct{}

func (kfr *KeyFileResolver) Resolve(name string) (key string, err error) {
	if strings.HasPrefix(name, "file://") {
		var keyBytes []byte
		keyBytes, err = os.ReadFile(name[len("file://"):])
		if err != nil {
			return
		}
		key = string(keyBytes)
	}
	return
}

func fixDNSResolver(dnsResolver *DNSResolver, defs ...*DNSResolver) error {
	if dnsResolver.Protocol == "" {
		if len(defs) > 0 {
			dr := defs[0]
			dnsResolver.Protocol = dr.Protocol
			dnsResolver.Servers = dr.Servers
		} else {
			dnsResolver.Protocol = DNSProtocolSYS
		}
	}
	switch dnsResolver.Protocol {
	case DNSProtocolSYS, DNSProtocolUDP, DNSProtocolTCP, DNSProtocolDOH, DNSProtocolQUIC:
	default:
		return fmt.Errorf("invalid dnsResolver protocol %s", dnsResolver.Protocol)
	}
	return nil
}

func NewNetConfigFromYaml(yamlData []byte, krs ...KeyResolver) (nc NetConfig, err error) {
	var container struct {
		NetConfig FlatNetConfig `yaml:"netConfig"`
	}
	err = yaml.Unmarshal(yamlData, &container)
	if err != nil {
		return
	}
	netConfig := container.NetConfig
	if netConfig.BaseDomain == "" {
		return nc, fmt.Errorf("baseDomain is empty")
	}
	if netConfig.DNSProvider == "" {
		return nc, fmt.Errorf("dnsProvider is empty")
	}
	err = fixDNSResolver(&netConfig.DNSResolver)
	if err != nil {
		return
	}

	err = fixHops(netConfig.Hops, &netConfig.DNSResolver)
	if err != nil {
		return
	}
	err = fixHopChains(&netConfig)
	if err != nil {
		return
	}
	err = flatToNetConfig(&netConfig, &nc)

	for i, hop := range nc.Hops {
		keyDone := false
		certDone := false
		for _, kr := range krs {
			if !keyDone {
				key, err := kr.Resolve(hop.Listen.Key)
				if err != nil {
					return nc, err
				}
				if key != "" {
					keyDone = true
					hop.Listen.Key = key
				}
			}
			if !certDone {
				cert, err := kr.Resolve(hop.Listen.Cert)
				if err != nil {
					return nc, err
				}
				if cert != "" {
					certDone = true
					hop.Listen.Cert = cert
				}
			}
		}
		nc.Hops[i] = hop
	}
	return
}
