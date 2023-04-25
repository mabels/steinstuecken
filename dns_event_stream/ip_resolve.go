package dns_event_stream

import (
	"github.com/miekg/dns"
)

type FixResolverSubject struct {
	Question dns.Question
	Result   []dns.RR
}

func (r *FixResolverSubject) ConnectActiveSubject(as *ActiveSubject) {
}

func (r *FixResolverSubject) Key() dns.Question {
	return r.Question
}

func (r *FixResolverSubject) Resolve() ([]dns.RR, error) {
	return r.Result, nil
}
