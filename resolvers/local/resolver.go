package local

import (
	"context"
	"fmt"
	"net"
	"time"

	"github.com/mabels/steinstuecken/resolvers"
)

type DNSEntry struct {
	ValidUntil time.Time
	Entry      string
	Results    []resolvers.DNSResult
	Resolvers  []*net.Resolver
}

type DNSCache struct {
	Entries map[string]DNSEntry
}

type LocalResolver struct {
	OnlyAuthoritative bool
	Timeout           time.Duration
	SysResolver       bool
	DNSServer         []string
	resolvers         []*net.Resolver
	cache             DNSCache
}

func append53(addr string) string {
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		return addr
	}
	if port == "" {
		port = "53"
	}
	return fmt.Sprintf("%s:%s", host, port)
}

func (r *LocalResolver) Resolve(name string) (resolvers.DNSResult, error) {
	if len(r.resolvers) == 0 {
		if r.SysResolver {
			r.resolvers = []*net.Resolver{net.DefaultResolver}
		} else {
			for _, addr := range r.DNSServer {
				r.resolvers = append(r.resolvers, &net.Resolver{
					PreferGo: !r.SysResolver,
					Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
						if r.Timeout == 0 {
							r.Timeout = 3 * time.Second
						}
						d := net.Dialer{
							Timeout: r.Timeout,
						}
						return d.DialContext(ctx, network, append53(addr))
					},
				})
			}
		}
	}
	for _, resolver := range r.resolvers {
		if r.OnlyAuthoritative {
			// test NS
			result, err := r.cache.LookupNS(name)

		}
		r.cache.L
		// test SRV
		// test CNAME
		// test A and AAAA
		ips, err := resolver.LookupIPAddr(context.Background(), name)
		if err == nil {
			return ips, nil
		}
	}

	return resolvers.DNSResult{}, nil
}
