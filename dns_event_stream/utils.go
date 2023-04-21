package dns_event_stream

import (
	"fmt"
	"math"
	"sort"
	"strings"
	"time"

	"github.com/miekg/dns"
)

func sortedUniq(rrs []dns.RR) []dns.RR {
	out := make([]dns.RR, 0, len(rrs))
	var last *string = nil
	for _, rr := range rrs {
		if last == nil || strings.Compare(rr.String(), *last) != 0 {
			val := rr.String()
			last = &val
			out = append(out, rr)
		} else {
			continue
		}
	}
	return out
}

func toActions(new, old []dns.RR) []actionItem {
	sort.Slice(new, func(a, b int) bool {
		return strings.Compare(new[a].String(), new[b].String()) < 0
	})
	new = sortedUniq(new)
	sort.Slice(old, func(a, b int) bool {
		return strings.Compare(old[a].String(), old[b].String()) < 0
	})
	old = sortedUniq(old)
	action := make([]actionItem, 0, int(math.Max(float64(len(new)), float64(len(old)))))
	for cnew := 0; cnew < len(new); cnew++ {
		if cnew >= len(old) {
			action = append(action, actionItem{
				action: "newAdd",
				idx:    cnew,
			})
			continue
		}
		if strings.Compare(new[cnew].String(), old[cnew].String()) == 0 {
			continue
		} else {
			action = append(action, actionItem{
				action: "change",
				idx:    cnew,
			})
		}
	}
	for cold := len(new); cold < len(old); cold++ {
		action = append(action, actionItem{
			action: "oldDel",
			idx:    cold,
		})
	}
	return action
}

func cleanName(s string) string {
	return strings.ToLower(strings.TrimSpace(strings.TrimRight(s, ".")))
}

func keySubject(q dns.Question) string {
	name := cleanName(q.Name)
	return fmt.Sprintf("%s:%s:%s", name, dns.ClassToString[q.Qclass], dns.TypeToString[q.Qtype])
}

func defaultMinRefreshTime(min time.Duration) time.Duration {
	if min < time.Second {
		return time.Second
	}
	return min
}
