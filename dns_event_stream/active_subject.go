package dns_event_stream

import (
	"context"
	"fmt"
	"math"
	"os"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/miekg/dns"
	"github.com/rs/zerolog"
)

type ActionItem struct {
	Action  string
	Idx     int
	Current dns.RR
	Prev    dns.RR
}

func (as *ActiveSubject) ensureLog() *zerolog.Logger {
	if as.Log == nil {
		if as.dnsEventStream != nil && as.dnsEventStream.log != nil {
			my := as.dnsEventStream.log.With().Str("activeSubject", as.Subject.Key().Name).Logger()
			as.Log = &my
		} else {
			my := zerolog.New(os.Stderr).With().Str("activeSubject", as.Subject.Key().Name).Logger()
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
	Subject            Subject
	Log                *zerolog.Logger
	activated          bool
	askBackend         sync.Mutex
	history            []*DnsResult
	dnsEventStream     *DnsEventStream
	isWaiting          bool
	cancelFn           func()
	doneBackendResolve chan []*DnsResult
	boundFns           map[string]func(history []*DnsResult)
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

func (as *ActiveSubject) Bind(fn func(history []*DnsResult)) func() {
	if as.boundFns == nil {
		as.boundFns = make(map[string]func(history []*DnsResult))
	}
	id := uuid.NewString()
	as.boundFns[id] = fn
	return func() {
		delete(as.boundFns, id)
	}
}

func unshift(new *DnsResult, history []*DnsResult) []*DnsResult {
	for i := len(history) - 1; i > 0; i-- {
		history[i] = history[i-1]
	}
	history[0] = new
	return history
}

func unshiftMax(new *DnsResult, history []*DnsResult, max int) []*DnsResult {
	if max < 1 {
		max = 1
	}
	if history == nil {
		history = make([]*DnsResult, 0, max)
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

	dnsrr := DnsResult{
		Created: as.dnsEventStream.time().Now(),
	}
	if as.history == nil {
		as.history = make([]*DnsResult, 0, as.dnsEventStream.HistoryLimit())
	}
	startTime := time.Now()
	dnsrr.Rrs, dnsrr.Err = as.Subject.Resolve()
	dnsrr.ResolveTime = time.Since(startTime)
	invokeBounds := false
	ai := []ActionItem{}
	if len(as.history) > 0 {
		last := LastValidHistory(as.history)
		ai = ToActions(dnsrr.Rrs, last.Rrs)
	}
	if len(as.history) == 0 {
		as.history = unshiftMax(&dnsrr, as.history, as.dnsEventStream.HistoryLimit())
		as.ensureLog().Debug().Any("history", as.history).Int("historyLen", len(as.history)).Msgf("init history: %v", ai)
		invokeBounds = true
	} else if len(ai) > 0 {
		as.history = unshiftMax(&dnsrr, as.history, as.dnsEventStream.HistoryLimit())
		as.ensureLog().Debug().Any("history", as.history).Int("historyLen", len(as.history)).Msgf("add history: %v", ai)
		invokeBounds = true
	}
	refreshTime := time.Second
	if dnsrr.Err == nil && len(dnsrr.Rrs) > 0 {
		nextTtl := math.MaxUint32
		for _, rr := range dnsrr.Rrs {
			if nextTtl > int(rr.Header().Ttl) {
				nextTtl = int(rr.Header().Ttl)
			}
		}
		refreshTime = time.Duration(nextTtl) * time.Second
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
		var ctx context.Context
		ctx, as.cancelFn = context.WithCancel(context.Background())
		as.isWaiting = true
		go func() {
			ret := as.dnsEventStream.timeIf.Delay(ctx, refreshTime)
			as.isWaiting = false
			as.cancelFn = nil
			if ret == nil {
				// as.dnsEventStream.time().Sleep(refreshTime)
				as.ensureLog().Debug().Dur("refreshing in ", refreshTime)
				as.Refresh()
			}
		}()
	}
	my := make([]*DnsResult, len(as.history))
	copy(my, as.history)
	defer as.askBackend.Unlock()
	if as.doneBackendResolve != nil {
		as.doneBackendResolve <- my
	}
	if invokeBounds {
		for _, fn := range as.boundFns {
			fn(my)
		}
	}
}

func (as *ActiveSubject) Resolve() DnsResult {
	// the start of the go routine makes the test flaky
	// if !as.activated {
	// 	go func() {
	// 		err := as.Activate()
	// 		if err != nil {
	// 			as.ensureLog().Warn().Err(err).Msg("activate failed")
	// 		}
	// 	}()
	// }

	if !as.activated {
		return DnsResult{
			Err: fmt.Errorf("subject not activated: %s", KeySubject(as.Subject.Key())),
		}
	}
	as.askBackend.Lock()
	defer as.askBackend.Unlock()
	dnsrr := DnsResult{
		// err:     fmt.Errorf("no history: %s", keySubject(as.Subject.Key())),
		Created: as.dnsEventStream.time().Now(),
	}
	if len(as.history) > 0 {
		// return latest error and first data from history
		dnsrr.Err = as.history[0].Err
		for _, rr := range as.history {
			if len(rr.Rrs) > 0 {
				dnsrr.Rrs = rr.Rrs
				break
			}
		}
	}
	return dnsrr
}

func (as *ActiveSubject) Activate() error {
	if as.activated {
		return fmt.Errorf("subject already activated: %s", KeySubject(as.Subject.Key()))
	}
	as.ensureLog().Info().Msg("Activate")
	as.activated = true
	as.Refresh()
	return nil
}

func (as *ActiveSubject) Deactivate() error {
	if !as.activated {
		return fmt.Errorf("subject not activated: %s", KeySubject(as.Subject.Key()))
	}
	if as.cancelFn != nil {
		as.cancelFn()
	}
	as.activated = false
	as.boundFns = make(map[string]func(history []*DnsResult))
	as.ensureLog().Info().Msg("Deactivate")
	return nil
}
