package dns_event_stream

import (
	"fmt"
	"log"
	"os"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/mabels/steinstuecken/resolvers"
)

type XSubject struct {
	Name       string
	Resolver   resolvers.Resolver
	LastUpdate time.Time
}

type DNSObserver struct {
	resolver     resolvers.Resolver
	results      chan resolvers.Result
	mutexSubject sync.Mutex
	subjects     map[string]XSubject
	running      bool
	logger       *log.Logger
}

func NewDNSObserver(logs ...*log.Logger) (*DNSObserver, error) {
	var logger *log.Logger
	if len(logs) > 0 {
		logger = logs[0]
	}
	if logger == nil {
		logger = log.New(os.Stdout, "observer: ", log.LstdFlags)
	}
	return &DNSObserver{
		results:  make(chan resolvers.Result, 16),
		subjects: make(map[string]XSubject),
		logger:   logger,
	}, nil
}

func (o *DNSObserver) AddSubject(name string, resolver resolvers.Resolver) XSubject {
	o.mutexSubject.Lock()
	defer o.mutexSubject.Unlock()
	o.subjects[name] = XSubject{
		Name:       name,
		Resolver:   resolver,
		LastUpdate: time.Now(),
	}
	o.logger.Printf("Added subject %v", o.subjects[name])
	return o.subjects[name]
}

func (o *DNSObserver) RemoveSubject(name string) *XSubject {
	o.mutexSubject.Lock()
	defer o.mutexSubject.Unlock()
	ret, found := o.subjects[name]
	if !found {
		return nil
	}
	o.logger.Printf("Remove subject %v", o.subjects[name])
	delete(o.subjects, name)
	return &ret
}

type subjectSorted []XSubject

func (sk subjectSorted) Len() int {
	return len(sk)
}

func (sk subjectSorted) Swap(i, j int) {
	(sk)[i], (sk)[j] = (sk)[j], (sk)[i]
}

func (sk subjectSorted) Less(i, j int) bool {
	return strings.Compare((sk)[i].Name, (sk)[j].Name) < 0
}

func (o *DNSObserver) GetSubjects() []XSubject {
	o.mutexSubject.Lock()
	subjects := make([]XSubject, 0, len(o.subjects))
	for _, subject := range o.subjects {
		subjects = append(subjects, subject)
	}
	defer o.mutexSubject.Unlock()
	sort.Sort(subjectSorted(subjects))
	return subjects
}

func (o *DNSObserver) Start() error {
	if o.running {
		return fmt.Errorf("observer already running")
	}
	o.running = true
	o.logger.Printf("Starting observer")
	wait := time.Duration(time.Second)
	for o.running {
		subs := o.GetSubjects()
		o.logger.Printf("Running for %d subjects", len(subs))
		// for range o.subjects {
		// }
		time.Sleep(wait)
	}
	o.logger.Printf("Stopped observer")
	return nil
}

func (o *DNSObserver) Stop() error {
	o.logger.Printf("Stopping observer")
	o.running = false
	return nil
}
