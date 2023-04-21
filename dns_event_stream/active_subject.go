package dns_event_stream

import (
	"fmt"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/miekg/dns"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
)

type actionItem struct {
	action string
	idx    int
}

func (as *ActiveSubject) ensureLog() *zerolog.Logger {
	if as.Log == nil {
		if !(as.dnsEventStream == nil && as.dnsEventStream.log == nil) {
			my := as.dnsEventStream.log.With().Str("activeSubject", as.Subject.Key().Name).Logger()
			as.Log = &my
		} else {
			my := log.With().Str("activeSubject", as.Subject.Key().Name).Logger()
			as.Log = &my
		}
	}
	return as.Log
}

type Subject interface {
	ConnectActiveSubject(as *ActiveSubject)
	Key() dns.Question
	Resolve() ([]dns.RR, error)
}

type ActiveSubject struct {
	Subject        Subject
	Log            *zerolog.Logger
	activated      bool
	askBackend     sync.Mutex
	history        []*dnsResult
	dnsEventStream *DnsEventStream
	isWaiting      bool
	boundFn        map[string]func(history []*dnsResult)
}

func NewActiveSubject(subject Subject, dnsEventStream *DnsEventStream) (*ActiveSubject, error) {
	if dnsEventStream == nil {
		return nil, fmt.Errorf("dnsEventStream is nil")
	}
	if subject == nil {
		return nil, fmt.Errorf("Subject is nil")
	}
	as := &ActiveSubject{
		Subject:        subject,
		dnsEventStream: dnsEventStream,
	}
	as.Subject.ConnectActiveSubject(as)
	return as, nil
}

func (as *ActiveSubject) Bind(fn func(history []*dnsResult)) func() {
	if as.boundFn == nil {
		as.boundFn = make(map[string]func(history []*dnsResult))
	}
	id := uuid.NewString()
	as.boundFn[id] = fn
	return func() {
		delete(as.boundFn, id)
	}
}

func unshift(new *dnsResult, history []*dnsResult) []*dnsResult {
	for i := len(history) - 1; i > 0; i-- {
		history[i] = history[i-1]
	}
	history[0] = new
	return history
}

func unshiftMax(new *dnsResult, history []*dnsResult, max int) []*dnsResult {
	if max < 1 {
		max = 1
	}
	if history == nil {
		history = make([]*dnsResult, 0, max)
	}
	if len(history) < max {
		history = append(history, new)
	}
	return unshift(new, history)
}

func (as *ActiveSubject) Refresh() {
	if !as.activated {
		as.ensureLog().Debug().Msg("not activated")
		return
	}
	as.askBackend.Lock()

	dnsrr := dnsResult{
		created: as.dnsEventStream.time().Now(),
	}
	if as.history == nil {
		as.history = make([]*dnsResult, 0, as.dnsEventStream.historyLimit)
	}
	dnsrr.rrs, dnsrr.err = as.Subject.Resolve()
	invokeBounds := false
	ai := []actionItem{}
	if len(as.history) > 0 {
		ai = toActions(dnsrr.rrs, as.history[0].rrs)
	}
	if len(as.history) == 0 {
		as.ensureLog().Debug().Msgf("init actions: %v", ai)
		as.history = unshiftMax(&dnsrr, as.history, as.dnsEventStream.historyLimit)
		invokeBounds = true
	} else if len(ai) > 0 {
		as.ensureLog().Debug().Msgf("actions: %v", ai)
		as.history = unshiftMax(&dnsrr, as.history, as.dnsEventStream.historyLimit)
		invokeBounds = true
	}
	refreshTime := time.Second
	if dnsrr.err == nil && len(dnsrr.rrs) > 0 {
		refreshTime = time.Duration(dnsrr.rrs[0].Header().Ttl) * time.Second
		if refreshTime > as.dnsEventStream.refreshTimes.overlay {
			refreshTime -= as.dnsEventStream.refreshTimes.overlay
		}
	}
	if refreshTime < defaultMinRefreshTime(as.dnsEventStream.refreshTimes.min) {
		refreshTime = defaultMinRefreshTime(as.dnsEventStream.refreshTimes.min)
	}
	if as.dnsEventStream.refreshTimes.max > defaultMinRefreshTime(as.dnsEventStream.refreshTimes.min) &&
		refreshTime > as.dnsEventStream.refreshTimes.max {
		refreshTime = as.dnsEventStream.refreshTimes.max
	}
	if !as.isWaiting {
		as.isWaiting = true
		go func() {
			as.dnsEventStream.time().Sleep(refreshTime)
			as.ensureLog().Debug().Dur("refreshing in ", refreshTime)
			as.isWaiting = false
			as.Refresh()
		}()
	}
	my := make([]*dnsResult, len(as.history))
	copy(my, as.history)
	defer as.askBackend.Unlock()
	if invokeBounds {
		for _, fn := range as.boundFn {
			fn(my)
		}
	}
}

func (as *ActiveSubject) Resolve() dnsResult {
	if !as.activated {
		return dnsResult{
			err: fmt.Errorf("subject not activated: %s", keySubject(as.Subject.Key())),
		}
	}
	as.askBackend.Lock()
	defer as.askBackend.Unlock()
	dnsrr := dnsResult{
		// err:     fmt.Errorf("no history: %s", keySubject(as.Subject.Key())),
		created: as.dnsEventStream.time().Now(),
	}
	if len(as.history) > 0 {
		// return latest error and first data from history
		dnsrr.err = as.history[0].err
		for _, rr := range as.history {
			if len(rr.rrs) > 0 {
				dnsrr.rrs = rr.rrs
				break
			}
		}
	}
	return dnsrr
}

func (as *ActiveSubject) Activate() error {
	if as.activated {
		return fmt.Errorf("subject already activated: %s", keySubject(as.Subject.Key()))
	}
	as.ensureLog().Info().Msg("Activate")
	as.activated = true
	as.Refresh()
	return nil
}

func (as *ActiveSubject) Deactivate() error {
	if !as.activated {
		return fmt.Errorf("subject not activated: %s", keySubject(as.Subject.Key()))
	}
	as.activated = false
	as.boundFn = make(map[string]func(history []*dnsResult))
	as.ensureLog().Info().Msg("Deactivate")
	return nil
}
