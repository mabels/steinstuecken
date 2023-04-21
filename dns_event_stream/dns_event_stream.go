package dns_event_stream

import (
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/miekg/dns"

	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
)

type dnsResult struct {
	rrs     []dns.RR
	err     error
	created time.Time
}

type RefreshTimes struct {
	min     time.Duration
	max     time.Duration // 0 means no max
	overlay time.Duration // 0 means no overlay
}

type DnsEventStream struct {
	activeLock     sync.Mutex
	activeSubjects map[string]*ActiveSubject
	log            *zerolog.Logger
	started        bool
	historyLimit   int // default 5
	refreshTimes   RefreshTimes
	waitResolve    time.Duration
	timeIf         timeInterface
}

func NewDnsEventStream(zlog *zerolog.Logger) *DnsEventStream {
	logger := zlog
	if zlog == nil {
		my := log.With().Str("component", "dns_event_stream").Logger()
		logger = &my
	}
	des := &DnsEventStream{
		activeSubjects: make(map[string]*ActiveSubject),
		log:            logger,
	}
	des.log.Info().Msg("created")
	return des
}

type sysTime struct{}

func (s *sysTime) Now() time.Time {
	return time.Now()
}

func (s *sysTime) Sleep(d time.Duration) {
	time.Sleep(d)
}

type timeInterface interface {
	Now() time.Time
	Sleep(time.Duration)
}

func (d *DnsEventStream) time() timeInterface {
	if d.timeIf != nil {
		return d.timeIf
	}
	d.timeIf = &sysTime{}
	return d.timeIf
}

func (s *DnsEventStream) Start() error {
	if s.started {
		return fmt.Errorf("already started")
	}
	s.started = true
	s.log.Info().Msg("Start")
	return nil
}

func (s *DnsEventStream) Stop() error {
	if !s.started {
		return fmt.Errorf("not started")
	}
	s.activeLock.Lock()
	defer s.activeLock.Unlock()
	for _, as := range s.activeSubjects {
		as.Deactivate()
	}
	s.started = false
	s.log.Info().Msg("Stop")
	return nil
}

func (s *DnsEventStream) AddSubject(sub Subject) (*ActiveSubject, error) {
	if !s.started {
		err := fmt.Errorf("not started")
		s.log.Error().Err(err)
		return nil, err
	}
	key := keySubject(sub.Key())
	aslog := s.log.With().Str("subject", key).Logger()
	var as *ActiveSubject
	{
		s.activeLock.Lock()
		defer s.activeLock.Unlock()
		var found bool
		as, found = s.activeSubjects[key]
		if found {
			aslog.Info().Msg("already added")
			return as, nil
		}
		as = &ActiveSubject{
			Subject:        sub,
			Log:            &aslog,
			dnsEventStream: s,
		}
		s.activeSubjects[key] = as
		as.Subject.ConnectActiveSubject(as)
	}
	s.log.Info().Str("subject", key).Msg("added")
	go func() {
		err := as.Activate()
		if err != nil {
			aslog.Warn().Err(err).Msg("activate failed")
		}
	}()
	return as, nil
}

func (s *DnsEventStream) RemoveSubject(q dns.Question) error {
	if !s.started {
		return fmt.Errorf("not started")
	}
	key := keySubject(q)
	s.activeLock.Lock()
	defer s.activeLock.Unlock()
	as, found := s.activeSubjects[key]
	if !found {
		err := fmt.Errorf("subject not found: %s", key)
		s.log.Error().Err(err)
		return err
	}
	err := as.Deactivate()
	if err != nil {
		return err
	}
	delete(s.activeSubjects, key)
	s.log.Info().Str("subject", key).Msg("removed")
	return nil
}

func (s *DnsEventStream) createActiveSubject(sub Subject) (bool, *ActiveSubject, error) {
	key := keySubject(sub.Key())
	s.activeLock.Lock()
	as, found := s.activeSubjects[key]
	s.activeLock.Unlock()
	if !found {
		var err error
		as, err = s.AddSubject(sub)
		if as == nil && err != nil {
			return !found, nil, err
		}
	}
	return !found, as, nil
}

func (s *DnsEventStream) Bind(sub Subject, fn func(history []*dnsResult)) (func(), error) {
	_, as, err := s.createActiveSubject(sub)
	if err != nil {
		return nil, err
	}
	return as.Bind(fn), nil
}

func (s *DnsEventStream) Resolve(sub Subject) ([]dns.RR, error) {
	_, as, err := s.createActiveSubject(sub)
	if err != nil {
		return nil, err
	}
	dnsrr := as.Resolve()
	if s.waitResolve == 0 {
		s.waitResolve = 100 * time.Millisecond
	}
	if dnsrr.err != nil && strings.HasPrefix(dnsrr.err.Error(), "subject not activated:") {
		s.log.Info().Str("subject", keySubject(sub.Key())).Msg("waiting for activation")
		time.Sleep(s.waitResolve)
		dnsrr = as.Resolve()
	}
	for ; dnsrr.err == nil && len(dnsrr.rrs) == 0; time.Sleep(s.waitResolve) {
		s.log.Info().Str("subject", keySubject(sub.Key())).Msg("waiting for results")
		// there should be a better way to do this
		dnsrr = as.Resolve()
	}
	return dnsrr.rrs, dnsrr.err
}
