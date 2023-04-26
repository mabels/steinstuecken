package config

type Operation struct {
	Op       OpAction    `json:"op"`
	Path     string      `json:"path"`
	PreValue interface{} `json:"preValue,omitempty"`
	NewValue interface{} `json:"newValue,omitempty"`
}

type Operations struct {
	Ops []Operation `json:"ops"`
}

func (ops *Operations) String(path, new, ref string) Operation {
	if new != ref {
		ops.Ops = append(ops.Ops, Operation{
			Op:       "update",
			Path:     path,
			PreValue: ref,
			NewValue: new,
		})
	}
}

func NetConfigOps(new *NetConfig, ref *NetConfig, ops *Operations) {
	ops.String("/baseDomain", new.BaseDomain, ref.BaseDomain)
	ops.String("/dnsProvider", new.DNSProvider, ref.DNSProvider)
	DNSResolverOps("/dnsResolver", new.DNSResolver, ref.DNSResolver, ops)
	ops.String("/description", new.Description, ref.Description)
	HopsOps("/hops", new.Hops, ref.Hops, ops)
	HopChainsOps("/hopChains", new.HopChains, ref.HopChains, ops)
	EndpointsOps("/endpoints", new.Endpoints, ref.Endpoints, ops)

}
