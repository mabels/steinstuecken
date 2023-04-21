package dns_event_stream

import (
	"fmt"
	"net"
	"os"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/miekg/dns"
	"github.com/rs/zerolog"
)

// func TestActiveSubject() {

// }

func TestSysResolverSubject(t *testing.T) {
	srs := SysResolverSubject{
		Question: dns.Question{
			Name:   "8.8.8.8.in-addr.arpa.",
			Qtype:  dns.TypePTR,
			Qclass: dns.ClassINET,
		},
		NameServers: []string{"8.8.8.8", "1.1.1.1"},
	}
	des := NewDnsEventStream(nil)
	err := des.Start()
	if err != nil {
		t.Fatalf("start: %v", err)
	}
	_, err = des.AddSubject(&srs)
	if err != nil {
		t.Fatalf("add: %v", err)
	}
	rrs, err := des.Resolve(&srs)
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	if len(rrs) != 1 {
		t.Fatalf("len(rrs) != 1")
	}
	if !strings.HasSuffix(rrs[0].String(), "dns.google.") {
		t.Errorf("%s != 8.8.8.8.in-addr.arpa.\t66354\tIN\tPTR\tdns.google.", rrs[0].String())
	}

	des.Stop()
}

func TestDnsEventStream(t *testing.T) {
	des := NewDnsEventStream(nil)
	err := des.Stop()
	if err.Error() != "not started" {
		t.Fatal(err)
	}
	sub := testSubject{
		question: dns.Question{
			Name: fmt.Sprintf("www.adviser.com"),
		},
	}
	_, err = des.AddSubject(&sub)
	if err.Error() != "not started" {
		t.Fatal(err)
	}
	err = des.RemoveSubject(sub.question)
	if err.Error() != "not started" {
		t.Fatal(err)
	}
	err = des.Start()
	if err != nil {
		t.Fatal(err)
	}
	err = des.Start()
	if err.Error() != "already started" {
		t.Fatal(err)
	}

	for i := 0; i < 10; i++ {
		sub = testSubject{
			question: dns.Question{
				Name: fmt.Sprintf("www%d.adviser.com", i),
			},
		}
		var as, das *ActiveSubject
		as, err = des.AddSubject(&sub)
		if err != nil {
			t.Fatal(err)
		}
		das, err = des.AddSubject(&sub)
		if err != nil {
			t.Fatalf("das, err = des.AddSubject(&sub) %v", err)
		}
		if as != das {
			t.Errorf("as != das")
		}
		_, found := des.activeSubjects[keySubject(sub.Key())]
		if !found {
			t.Fatal("not found")
		}
	}

	for i := 0; i < 10; i++ {
		sub = testSubject{
			question: dns.Question{
				Name: fmt.Sprintf("www%d.adviser.com", i),
			},
		}
		pre := des.activeSubjects[keySubject(sub.question)]
		err = des.RemoveSubject(sub.question)
		if err != nil {
			t.Fatal(err)
		}
		err := des.RemoveSubject(sub.question)
		if !strings.HasPrefix(err.Error(), "subject not found") {
			t.Fatal(err)
		}
		err = pre.Deactivate()
		if !strings.HasPrefix(err.Error(), "subject not activated") {
			t.Fatal(err)
		}
	}
	err = des.Stop()
	if err != nil {
		t.Fatal(err)
	}
	err = des.Stop()
	if err.Error() != "not started" {
		t.Fatal(err)
	}
}

type testRR struct {
	dns.RR
	_string string
	_header dns.RR_Header
}

func (rr *testRR) Header() *dns.RR_Header {
	// return &rr._header
	return nil
}

func (rr *testRR) String() string {
	return rr._string
}

func (rr *testRR) copy() dns.RR {
	return &testRR{
		_string: rr._string,
		_header: rr._header,
	}
}

func TestToActions(t *testing.T) {
	ai := toActions([]dns.RR{}, []dns.RR{})
	if len(ai) != 0 {
		t.Fatal("ai should be empty")
	}
	dup := &testRR{_string: "result", _header: dns.RR_Header{Name: "question"}}
	// equal
	ai = toActions([]dns.RR{dup, dup}, []dns.RR{dup, dup})
	if len(ai) != 0 {
		t.Fatal("ai should be empty")
	}
	// new
	ai = toActions([]dns.RR{dup, dup}, []dns.RR{})
	if len(ai) != 1 {
		t.Fatalf("ai should be 1: %v", len(ai))
	}
	if ai[0].action != "newAdd" {
		t.Fatalf("ai should be newAdd: %v", ai[0].action)
	}
	if ai[0].idx != 0 {
		t.Fatalf("ai should be 0: %v", ai[0].idx)
	}

	// del
	ai = toActions([]dns.RR{}, []dns.RR{dup, dup})
	if len(ai) != 1 {
		t.Fatalf("ai should be 1: %v", len(ai))
	}
	if ai[0].action != "oldDel" {
		t.Fatalf("ai should be oldDel: %v", ai[0].action)
	}
	if ai[0].idx != 0 {
		t.Fatalf("ai should be 0: %v", ai[0].idx)
	}

	dup1 := &testRR{_string: "result1", _header: dns.RR_Header{Name: "question1"}}
	ai = toActions([]dns.RR{dup, dup1}, []dns.RR{dup})
	if len(ai) != 1 {
		t.Fatalf("ai should be 1: %v", len(ai))
	}
	if ai[0].action != "newAdd" {
		t.Fatalf("ai should be oldDel: %v", ai[0].action)
	}
	if ai[0].idx != 1 {
		t.Fatalf("ai should be 0: %v", ai[1].idx)
	}

	dup2 := &testRR{_string: "result2", _header: dns.RR_Header{Name: "question2"}}
	ai = toActions([]dns.RR{dup, dup2}, []dns.RR{dup, dup1})
	if len(ai) != 1 {
		t.Fatalf("ai should be 1: %v", len(ai))
	}
	if ai[0].action != "change" {
		t.Fatalf("ai should be change: %v", ai[0].action)
	}
	if ai[0].idx != 1 {
		t.Fatalf("ai should be 0: %v", ai[1].idx)
	}

	ai = toActions([]dns.RR{dup, dup2, dup1}, []dns.RR{dup, dup1})
	if len(ai) != 1 {
		t.Fatalf("ai should be 1: %v", len(ai))
	}
	if ai[0].action != "newAdd" {
		t.Fatalf("ai should be change: %v", ai[0].action)
	}
	if ai[0].idx != 2 {
		t.Fatalf("ai should be 0: %v", ai[1].idx)
	}

	ai = toActions([]dns.RR{dup, dup2, dup1}, []dns.RR{dup})
	if len(ai) != 2 {
		t.Fatalf("ai should be 1: %v", len(ai))
	}
	if ai[0].action != "newAdd" {
		t.Fatalf("ai should be change: %v", ai[0].action)
	}
	if ai[0].idx != 1 {
		t.Fatalf("ai should be 0: %v", ai[0].idx)
	}

	if ai[1].action != "newAdd" {
		t.Fatalf("ai should be change: %v", ai[1].action)
	}
	if ai[1].idx != 2 {
		t.Fatalf("ai should be 0: %v", ai[1].idx)
	}
}

type testSubject struct {
	question      dns.Question
	err           error
	activeSubject *ActiveSubject
	doTtl         bool
	// rrs      []dns.RR
	calls struct {
		resolve int
		key     int
	}
	log *zerolog.Logger
}

func (ts *testSubject) ensureLog() *zerolog.Logger {
	if ts.activeSubject != nil {
		zlog := ts.activeSubject.ensureLog().With().Str("key", keySubject(ts.question)).Timestamp().Logger()
		ts.log = &zlog
	} else if ts.log == nil {
		zlog := zerolog.New(os.Stderr).With().Str("key", keySubject(ts.question)).Timestamp().Logger()
		ts.log = &zlog
	}
	return ts.log
}

func (ts *testSubject) ConnectActiveSubject(as *ActiveSubject) {
	ts.activeSubject = as
}

func (ts *testSubject) Key() dns.Question {
	ts.calls.key++
	return ts.question
}

func (ts *testSubject) Resolve() ([]dns.RR, error) {
	ts.calls.resolve++
	ts.ensureLog().Debug().Msgf("resolve %d", ts.calls.resolve/3)
	ttl := 10
	if ts.doTtl {
		ttl = ts.calls.resolve
	}
	ts.ensureLog().Debug().Msgf("resolve %d-%d:%d", ttl, ts.calls.resolve, ts.calls.resolve/3)
	my := new(dns.A)
	my.Hdr = dns.RR_Header{Name: "test", Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: uint32(ttl)}
	my.A = net.ParseIP(fmt.Sprintf("%d.0.0.0", ts.calls.resolve/3))
	rrs := make([]dns.RR, 1)
	rrs[0] = my
	return rrs, ts.err
}

func TestActiveResolve(t *testing.T) {
	ts := testSubject{
		question: dns.Question{Name: "test", Qtype: dns.TypeA, Qclass: dns.ClassINET},
	}
	zlog := zerolog.New(os.Stderr).With().Timestamp().Logger()
	as, err := NewActiveSubject(&ts, &DnsEventStream{
		historyLimit: 5,
		log:          &zlog,
		refreshTimes: RefreshTimes{
			min:     time.Second,
			max:     time.Minute,
			overlay: 0,
		},
	})
	if err != nil {
		t.Error(err)
	}

	var bound []*dnsResult
	as.Bind(func(history []*dnsResult) {
		bound = history
	})

	err = as.Activate()
	if err != nil {
		t.Errorf("err should be nil: %v", err)
	}
	defer func() {
		err := as.Deactivate()
		if err != nil {
			t.Errorf("err should be nil: %v", err)
		}
	}()
	rs := as.Resolve()
	if len(rs.rrs) != 1 {
		t.Fatalf("rrs should be 1: %v", len(rs.rrs))
	}
	if rs.rrs[0].String() != "test	10	IN	A	0.0.0.0" {
		t.Errorf("rrs should be test. 10 IN A: %v", rs.rrs[0].String())
	}
	if rs.err != nil {
		t.Errorf("err should be nil:%v", rs.err)
	}
	if len(as.history) != 1 {
		t.Error("history should be 1")
	}
	if reflect.DeepEqual(as.history, bound) == false {
		t.Errorf("history should be bound: %v", bound)
	}
}

type mockTime struct {
	nows   []time.Time
	sleeps []time.Duration
}

func (mt *mockTime) Now() time.Time {
	if mt.nows == nil {
		mt.nows = []time.Time{}
	}
	mt.nows = append(mt.nows, time.Now())
	return mt.nows[len(mt.nows)-1]
}

func (mt *mockTime) Sleep(d time.Duration) {
	if mt.sleeps == nil {
		mt.sleeps = []time.Duration{}
	}
	mt.sleeps = append(mt.sleeps, d)
	time.Sleep(10 * time.Millisecond)
}

func TestUnshift(t *testing.T) {
	history := make([]*dnsResult, 0, 4)
	for i := 0; i < 8; i++ {
		out := unshiftMax(&dnsResult{rrs: []dns.RR{&dns.A{
			Hdr: dns.RR_Header{
				Name:   "test",
				Rrtype: dns.TypeA,
				Class:  dns.ClassINET,
				Ttl:    uint32(i),
			},
			A: net.ParseIP(fmt.Sprintf("%d.0.0.0", i)),
		}}}, history, 4)
		// if &out != &history {
		// 	t.Errorf("out should be history: %v:%v", &out, &history)
		// }
		history = out
		if i < 4 && len(history) != i+1 {
			t.Errorf("history should be %d: %v", i+1, len(history))
		} else if i >= 4 && len(history) != 4 {
			t.Errorf("history should be 4: %v", len(history))
		}
		j := 0
		for k := len(history) - 1; k >= 0; k-- {
			should := fmt.Sprintf("test	%d	IN	A	%d.0.0.0", i-j, i-j)
			if history[j].rrs[0].String() != should {
				t.Errorf("rrs should be %d:%d:%d:[%v]==[%v]", len(history), k, i, history[j].rrs[0].String(), should)
			}
			j++
		}
	}
}

func TestActiveBind(t *testing.T) {
	ts := testSubject{
		doTtl:    true,
		question: dns.Question{Name: "test", Qtype: dns.TypeA, Qclass: dns.ClassINET},
	}
	mockTime := &mockTime{}
	zlog := zerolog.New(os.Stderr).With().Timestamp().Logger()
	as, err := NewActiveSubject(&ts, &DnsEventStream{
		historyLimit: 3,
		log:          &zlog,
		timeIf:       mockTime,
		refreshTimes: RefreshTimes{
			min:     3 * time.Second,
			max:     7 * time.Second,
			overlay: 0,
		},
	})
	if err != nil {
		t.Error(err)
	}

	bounds := [][]*dnsResult{}
	as.Bind(func(history []*dnsResult) {
		bounds = append(bounds, history)
		out := make([][]string, 0, len(bounds))
		for _, bs := range bounds {
			bsStrs := make([]string, len(bs))
			for _, b := range bs {
				for _, r := range b.rrs {
					bsStrs = append(bsStrs, r.String())
				}
			}
			out = append(out, bsStrs)
		}
		zlog.Debug().Msgf("bound: %v:%v", out, history)
	})

	err = as.Activate()
	if err != nil {
		t.Errorf("err should be nil: %v", err)
	}
	time.Sleep(time.Millisecond * 105)
	err = as.Deactivate()
	if err != nil {
		t.Errorf("err should be nil: %v", err)
	}
	if len(bounds) != 10 {
		t.Errorf("bound should be 10: %v", len(bounds))
	}
	for i, b := range bounds {
		if i < 3 && len(b) != i+1 {
			t.Errorf("should be %v: %v", i+1, len(b))
		}
		if i >= 4 && len(b) != 3 {
			t.Errorf("should be %v: %v", i+1, len(b))
		}
		for j, r := range b {
			x := (1 + i) - j
			should := fmt.Sprintf("test	%d	IN	A	%d.0.0.0", x, x/3)
			if r.rrs[0].String() != should {
				t.Errorf("should be %d:%d:%d [%v]:[%v]", i, j, len(b), should, r.rrs[0].String())
			}
		}
	}
	if len(mockTime.nows) != 10 {
		t.Errorf("nows should be 10: %v", len(mockTime.nows))
	}
	if len(mockTime.sleeps) != 10 {
		t.Errorf("sleeps should be 10: %v", len(mockTime.sleeps))
	}
	if !reflect.DeepEqual(mockTime.sleeps, []time.Duration{
		3 * time.Second, 3 * time.Second, 3 * time.Second,
		4 * time.Second,
		5 * time.Second,
		6 * time.Second,
		7 * time.Second, 7 * time.Second, 7 * time.Second, 7 * time.Second}) {
		t.Errorf("nows should not be same: %v:%v", mockTime.sleeps, mockTime.sleeps)
	}
	if ts.calls.resolve != 10 {
		t.Errorf("calls.resolve should be 10: %v", ts.calls.resolve)
	}

}

func TestDnsEventStreamRunning(t *testing.T) {
	zlog := zerolog.New(os.Stderr).With().Timestamp().Logger()
	des := NewDnsEventStream(&zlog)
	des.timeIf = &mockTime{}
	des.waitResolve = 3 * time.Millisecond
	// des.

	err := des.Start()
	if err != nil {
		t.Errorf("err should be nil: %v", err)
	}
	defer des.Stop()

	ts := testSubject{
		question: dns.Question{Name: "test", Qtype: dns.TypeA, Qclass: dns.ClassINET},
	}
	bounds := []string{}
	_, err = des.Bind(&ts, func(history []*dnsResult) {
		bounds = append(bounds, history[0].rrs[0].String())
	})
	if err != nil {
		t.Errorf("err should be nil: %v", err)
	}
	out := make([]string, 0, 10)
	for i := 0; i < 10; i++ {
		rrs, err := des.Resolve(&ts)
		if err != nil {
			t.Errorf("err should be nil: %v", err)
		}
		if len(rrs) != 1 {
			t.Errorf("rrs should be 1: %v", len(rrs))
		}
		out = append(out, rrs[0].String())
		time.Sleep(10500 * time.Microsecond)
	}
	des.Stop()
	time.Sleep(22 * time.Millisecond)
	if !reflect.DeepEqual(out, []string{
		"test	10	IN	A	0.0.0.0", "test	10	IN	A	0.0.0.0",
		"test	10	IN	A	1.0.0.0", "test	10	IN	A	1.0.0.0", "test	10	IN	A	1.0.0.0",
		"test	10	IN	A	2.0.0.0", "test	10	IN	A	2.0.0.0", "test	10	IN	A	2.0.0.0",
		"test	10	IN	A	3.0.0.0", "test	10	IN	A	3.0.0.0",
	}) {
		t.Errorf("out should be same: %v", out)
	}
	if len(bounds) != 4 {
		t.Errorf("bounds should be 4: %v", len(bounds))
	}
	if !reflect.DeepEqual(bounds, []string{
		"test	10	IN	A	0.0.0.0",
		"test	10	IN	A	1.0.0.0",
		"test	10	IN	A	2.0.0.0",
		"test	10	IN	A	3.0.0.0",
	}) {
		t.Errorf("bounds should be same: %v", bounds)
	}

}