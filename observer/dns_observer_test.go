package observer


import (
	"sync"
	"fmt"
	"io"
	"log"
	"testing"

	"github.com/mabels/steinstuecken/resolvers/local"
)

var noLogger = log.New(io.Discard, "noLogger: ", log.LstdFlags)


func TestSimpleNewObserver(t *testing.T) {
	_, err := NewDNSObserver(noLogger);
	if err != nil {
		t.Error(err)
	}
}

func TestStartStop(t *testing.T) {
	obs, err := NewDNSObserver(noLogger);
	if err != nil {
		t.Error(err)
	}
	wg := sync.WaitGroup{}
	wgStop := sync.WaitGroup{}
	wg.Add(1)
	wgStop.Add(1)
	go func() {
		wg.Done()
		obs.Start()
		wgStop.Done()
	}()
	wg.Wait()
	if !obs.running {
		t.Error("Observer not running")
	}
	obs.Stop()
	wgStop.Wait()
	if obs.running {
		t.Error("Observer still running")
	}
}


func TestSubjects(t *testing.T) {
	obs, err := NewDNSObserver() 
	if err != nil {
		t.Error(err)
	}
	var subs []Subject
	subs = obs.GetSubjects()
	if len(subs) != 0 {
		t.Errorf("Subjects not right:%d", len(subs))
	}
	for i := 0; i < 10; i++ {
		for j := 0; j < 10; j++ {
			domain := fmt.Sprintf("www%d.adviser.com", i)
			sub := obs.AddSubject(domain, &local.LocalResolver{})
			if sub.Name != domain {
				t.Error("Subject name not set")	
			}
			_, ok := sub.Resolver.(*local.LocalResolver)
			if !ok {
				t.Error("Subject resolver not set")	
			}
			subs = obs.GetSubjects()
			if len(subs) != i+1 {
				t.Errorf("Subject not added:%d:%d", len(subs), i)
			}
			if subs[i].Name != domain {
				t.Error("Subject name not set", subs[i].Name, domain)
			}
		}
	}
	subs = obs.GetSubjects()
	if len(subs) != 10 {
		t.Errorf("Subjects not right:%d", len(subs))
	}
	sub := obs.RemoveSubject("notexisting")
	if sub != nil {
		t.Error("Subject removed")
	}
	for i := 0; i < 10; i++ {
		domain := fmt.Sprintf("www%d.adviser.com", i)
		sub := obs.RemoveSubject(domain)
		if sub == nil {
			t.Error("Subject not removed")
		}
		if sub.Name != domain {
			t.Error("Subject name not set")
		}
		sub = obs.RemoveSubject(domain)
		if sub != nil {
			t.Error("Subject removed")
		}
		subs = obs.GetSubjects()
		if len(subs) != 9-i {
			t.Errorf("Subject not removed:%d:%d", len(subs), i)
		}
	}
	subs = obs.GetSubjects()
	if len(subs) != 0 {
		t.Errorf("Subjects not empty:%d", len(subs))
	}
}

