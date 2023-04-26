package dns_event_stream

import (
	"fmt"
	"math"
	"net"
	"sort"
	"strings"
	"time"

	"github.com/miekg/dns"
)

func canonicalIP(bytes net.IP) string {
	out := ""
	for i := 0; i < len(bytes); i++ {
		out += fmt.Sprintf("%03d-", bytes[i])
	}
	return out
}

func sortedUniq(rrs []dns.RR) []dns.RR {
	out := make([]dns.RR, 0, len(rrs))
	var last *string = nil
	for _, rr := range rrs {
		str := rr.String()
		dnsA, found := rr.(*dns.A)
		if found {
			str = canonicalIP(dnsA.A)
		}
		dnsAAAA, found := rr.(*dns.AAAA)
		if found {
			str = canonicalIP(dnsAAAA.AAAA)
		}
		if last == nil || strings.Compare(str, *last) != 0 {
			last = &str
			out = append(out, rr)
		} else {
			continue
		}
	}
	return out
}

func NewestValidHistory(history []*DnsResult) *DnsResult {
	if len(history) == 0 {
		return &DnsResult{}
	}
	for i := 0; i < len(history); i++ {
		if history[i].Err == nil {
			return history[i]
		}
	}
	return &DnsResult{}
}

func CurrentToActions(dnsrr []*DnsResult) []ActionItem {
	if len(dnsrr) == 0 {
		return []ActionItem{}
	}
	if len(dnsrr) == 1 {
		return ToActions(dnsrr[0].Rrs, []dns.RR{})
	}
	if dnsrr[0].Err != nil {
		return []ActionItem{}
	}
	last := NewestValidHistory(dnsrr)
	return ToActions(dnsrr[0].Rrs, last.Rrs)
}

func canonicalStr(rr dns.RR) string {
	str := rr.String()
	dnsA, found := rr.(*dns.A)
	if found {
		str = canonicalIP(dnsA.A)
	}
	dnsAAAA, found := rr.(*dns.AAAA)
	if found {
		str = canonicalIP(dnsAAAA.AAAA)
	}
	return str
}

func dnsSort(rrs []dns.RR) func(a, b int) bool {
	return func(a, b int) bool {
		return strings.Compare(canonicalStr(rrs[a]), canonicalStr(rrs[b])) < 0
	}
}

func ToActions(new, old []dns.RR) []ActionItem {
	sort.Slice(new, dnsSort(new))
	new = sortedUniq(new)
	sort.Slice(old, dnsSort(old))
	old = sortedUniq(old)
	action := make([]ActionItem, 0, int(math.Max(float64(len(new)), float64(len(old)))))
	for cnew := 0; cnew < len(new); cnew++ {
		if cnew >= len(old) {
			action = append(action, ActionItem{
				Action:  "newAdd",
				Idx:     cnew,
				Current: new[cnew],
			})
			continue
		}
		if strings.Compare(new[cnew].String(), old[cnew].String()) == 0 {
			continue
		} else {
			action = append(action, ActionItem{
				Action:  "change",
				Idx:     cnew,
				Current: new[cnew],
				Prev:    old[cnew],
			})
		}
	}
	for cold := len(new); cold < len(old); cold++ {
		action = append(action, ActionItem{
			Action: "oldDel",
			Idx:    cold,
			Prev:   old[cold],
		})
	}
	return action
}

func cleanName(s string) string {
	return strings.ToLower(strings.TrimSpace(strings.TrimRight(s, ".")))
}

func KeySubject(q dns.Question) string {
	name := cleanName(q.Name)
	return fmt.Sprintf("%s:%s:%s", name, dns.ClassToString[q.Qclass], dns.TypeToString[q.Qtype])
}

func defaultMinRefreshTime(min time.Duration) time.Duration {
	if min < time.Second {
		return time.Second
	}
	return min
}
