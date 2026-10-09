package transport

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"net/http"
	"sort"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/xssnick/tonutils-go/adnl/address"
	"github.com/xssnick/tonutils-go/adnl/rldp"
	"github.com/xssnick/tonutils-go/tl"
	"github.com/xssnick/tonutils-go/ton/dns"
	"github.com/xssnick/tonutils-go/tvm/cell"
)

// ---- fakes ----

func siteDomain(t *testing.T, adnlID []byte) *dns.Domain {
	t.Helper()
	d := cell.NewDict(256)
	h := sha256.Sum256([]byte("site"))
	key := cell.BeginCell().MustStoreSlice(h[:], 256).EndCell()
	val := cell.BeginCell().MustStoreRef(
		cell.BeginCell().MustStoreUInt(0xad01, 16).MustStoreSlice(adnlID, 256).EndCell(),
	).EndCell()
	if err := d.Set(key, val); err != nil {
		t.Fatal(err)
	}
	return &dns.Domain{Records: d}
}

type fakeResolver struct {
	calls atomic.Int32
	fn    func(ctx context.Context, call int32) (*dns.Domain, error)
}

func (r *fakeResolver) Resolve(ctx context.Context, _ string) (*dns.Domain, error) {
	return r.fn(ctx, r.calls.Add(1))
}

type fakeDHT struct {
	calls atomic.Int32
	addrs []string
}

func (d *fakeDHT) StoreAddress(context.Context, address.List, time.Duration, ed25519.PrivateKey) (int, []byte, error) {
	return 0, nil, nil
}
func (d *fakeDHT) FindAddresses(ctx context.Context, id []byte) (*address.List, ed25519.PublicKey, error) {
	d.calls.Add(1)
	l := &address.List{}
	for _, a := range d.addrs {
		host, port, _ := net.SplitHostPort(a)
		var p int32
		fmt.Sscan(port, &p)
		l.Addresses = append(l.Addresses, &address.UDP{IP: net.ParseIP(host), Port: p})
	}
	seed := sha256.Sum256(id) // one server key per ADNL id, as in the real DHT
	pub := ed25519.NewKeyFromSeed(seed[:]).Public().(ed25519.PublicKey)
	return l, pub, nil
}
func (d *fakeDHT) Close() {}

// fakeRLDP answers the HTTP request header query, or stalls until the ctx ends.
type fakeRLDP struct {
	addr     string
	stall    bool
	closed   atomic.Bool
	mx       sync.Mutex
	onDiscon func()
}

// Close fires the disconnect handler asynchronously, as the real ADNL gateway does.
func (f *fakeRLDP) Close() {
	if f.closed.Swap(true) {
		return
	}
	f.mx.Lock()
	h := f.onDiscon
	f.mx.Unlock()
	if h != nil {
		go h()
	}
}
func (f *fakeRLDP) SetOnQuery(func([]byte, *rldp.Query) error) {}
func (f *fakeRLDP) SetOnDisconnect(h func()) {
	f.mx.Lock()
	f.onDiscon = h
	f.mx.Unlock()
}
func (f *fakeRLDP) GetADNL() rldp.ADNL { return nil }
func (f *fakeRLDP) SendAnswer(context.Context, uint64, uint32, []byte, []byte, tl.Serializable) error {
	return nil
}
func (f *fakeRLDP) DoQuery(ctx context.Context, _ uint64, _, result tl.Serializable) error {
	if f.stall {
		<-ctx.Done()
		return ctx.Err()
	}
	if r, ok := result.(*Response); ok {
		*r = Response{Version: "HTTP/1.1", StatusCode: 200, Reason: "OK", NoPayload: true}
	}
	return nil
}

func newTestTransport(res Resolver, dht DHT) *Transport {
	t := &Transport{
		dht:            dht,
		resolver:       res,
		activeRequests: map[string]*payloadStream{},
		activeSites:    map[string]*siteInfo{},
		dns:            newDNSCache(),
		dhtCache:       map[string]*dhtRecord{},
		servers:        map[string]*serverClient{},
	}
	t.globalCtx, t.stop = context.WithCancel(context.Background())
	return t
}

var testID = make([]byte, 32)

func okResolver(t *testing.T, delay time.Duration) *fakeResolver {
	return &fakeResolver{fn: func(ctx context.Context, _ int32) (*dns.Domain, error) {
		select {
		case <-time.After(delay):
			return siteDomain(t, testID), nil
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}}
}

// ---- DNS ----

func TestLookupIsCached(t *testing.T) {
	r := okResolver(t, 10*time.Millisecond)
	tr := newTestTransport(r, &fakeDHT{})
	defer tr.stop()

	for i := 0; i < 5; i++ {
		rec, err := tr.lookup(context.Background(), "a.ton")
		if err != nil || rec.inStorage {
			t.Fatalf("lookup %d: %v %+v", i, err, rec)
		}
	}
	if n := r.calls.Load(); n != 1 {
		t.Fatalf("resolver calls = %d, want 1", n)
	}
}

func TestStaleEntryAnswersAtOnceAndRefreshesInBackground(t *testing.T) {
	r := okResolver(t, 200*time.Millisecond)
	tr := newTestTransport(r, &fakeDHT{})
	defer tr.stop()
	tr.dns.entries["a.ton"] = &dnsRecord{id: testID, at: time.Now().Add(-DNSFreshFor - time.Second)}

	tm := time.Now()
	if _, err := tr.lookup(context.Background(), "a.ton"); err != nil {
		t.Fatal(err)
	}
	if d := time.Since(tm); d > 50*time.Millisecond {
		t.Fatalf("stale lookup waited %v; it must answer from cache", d)
	}
	time.Sleep(400 * time.Millisecond)
	tr.dns.mx.Lock()
	age := time.Since(tr.dns.entries["a.ton"].at)
	tr.dns.mx.Unlock()
	if age > time.Second || r.calls.Load() != 1 {
		t.Fatalf("background refresh did not run (age %v, calls %d)", age, r.calls.Load())
	}
}

func TestNoHotRetryLoop(t *testing.T) {
	r := &fakeResolver{fn: func(context.Context, int32) (*dns.Domain, error) {
		return nil, errors.New("deadline exceeded, node x")
	}}
	tr := newTestTransport(r, &fakeDHT{})
	defer tr.stop()

	_, err := tr.lookup(context.Background(), "a.ton")
	if err == nil {
		t.Fatal("want error")
	}
	// upstream: three goroutines retrying without backoff until the caller's ctx ended
	if n := r.calls.Load(); n > int32(len(dnsAttemptStarts)) {
		t.Fatalf("resolver calls = %d, want <= %d", n, len(dnsAttemptStarts))
	}
}

func TestHedgedAttemptBeatsASlowLiteserver(t *testing.T) {
	old := dnsAttemptStarts
	dnsAttemptStarts = []time.Duration{0, 50 * time.Millisecond, 100 * time.Millisecond}
	defer func() { dnsAttemptStarts = old }()

	r := &fakeResolver{}
	r.fn = func(ctx context.Context, call int32) (*dns.Domain, error) {
		if call == 1 { // first attempt hits a stuck liteserver
			<-ctx.Done()
			return nil, ctx.Err()
		}
		return siteDomain(t, testID), nil
	}
	tr := newTestTransport(r, &fakeDHT{})
	defer tr.stop()

	tm := time.Now()
	if _, err := tr.lookup(context.Background(), "a.ton"); err != nil {
		t.Fatal(err)
	}
	if d := time.Since(tm); d > time.Second {
		t.Fatalf("took %v; the second attempt should answer after ~50ms", d)
	}
}

func TestNoSuchRecordIsRemembered(t *testing.T) {
	r := &fakeResolver{fn: func(context.Context, int32) (*dns.Domain, error) { return nil, dns.ErrNoSuchRecord }}
	tr := newTestTransport(r, &fakeDHT{})
	defer tr.stop()
	for i := 0; i < 3; i++ {
		if _, err := tr.lookup(context.Background(), "gone.ton"); !errors.Is(err, dns.ErrNoSuchRecord) {
			t.Fatalf("want ErrNoSuchRecord, got %v", err)
		}
	}
	if n := r.calls.Load(); n != 1 {
		t.Fatalf("resolver calls = %d, want 1", n)
	}
}

// ---- connecting ----

func TestOneConnectForManyConcurrentRequests(t *testing.T) {
	r := okResolver(t, 100*time.Millisecond)
	tr := newTestTransport(r, &fakeDHT{addrs: []string{"1.2.3.4:1"}})
	defer tr.stop()
	var dials atomic.Int32
	tr.dialRLDP = func(_ ed25519.PublicKey, addr, _ string) (RLDP, error) {
		dials.Add(1)
		return &fakeRLDP{addr: addr}, nil
	}

	var wg sync.WaitGroup
	for i := 0; i < 20; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if _, err := tr.actorFor(context.Background(), "a.ton", nil); err != nil {
				t.Error(err)
			}
		}()
	}
	wg.Wait()
	if dials.Load() != 1 || r.calls.Load() != 1 {
		t.Fatalf("dials = %d, resolves = %d; want 1 and 1", dials.Load(), r.calls.Load())
	}
}

func TestAWaiterGivesUpWithoutBlockingOthers(t *testing.T) {
	r := okResolver(t, 300*time.Millisecond)
	tr := newTestTransport(r, &fakeDHT{addrs: []string{"1.2.3.4:1"}})
	defer tr.stop()
	tr.dialRLDP = func(_ ed25519.PublicKey, addr, _ string) (RLDP, error) { return &fakeRLDP{addr: addr}, nil }

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	tm := time.Now()
	if _, err := tr.actorFor(ctx, "a.ton", nil); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("want deadline, got %v", err)
	}
	if d := time.Since(tm); d > 100*time.Millisecond {
		t.Fatalf("waiter held for %v; upstream waited on an uncancellable lock", d)
	}
	// the connect kept going in the background: the next request finds the site ready
	time.Sleep(400 * time.Millisecond)
	tm = time.Now()
	if _, err := tr.actorFor(context.Background(), "a.ton", nil); err != nil {
		t.Fatal(err)
	}
	if d := time.Since(tm); d > 50*time.Millisecond {
		t.Fatalf("second request waited %v", d)
	}
}

func TestStalledConnectionIsDroppedAndRetriedFresh(t *testing.T) {
	old := RLDPHeaderTimeout
	RLDPHeaderTimeout = 100 * time.Millisecond
	defer func() { RLDPHeaderTimeout = old }()

	dht := &fakeDHT{addrs: []string{"1.2.3.4:1", "5.6.7.8:2"}}
	tr := newTestTransport(okResolver(t, time.Millisecond), dht)
	defer tr.stop()
	var clients []*fakeRLDP
	tr.dialRLDP = func(_ ed25519.PublicKey, addr, _ string) (RLDP, error) {
		c := &fakeRLDP{addr: addr, stall: len(clients) == 0} // the first connection is dead
		clients = append(clients, c)
		return c, nil
	}

	req, _ := http.NewRequest(http.MethodGet, "http://a.ton/", nil)
	req.Host = "a.ton"
	resp, err := tr.RoundTrip(req)
	if err != nil || resp.StatusCode != 200 {
		t.Fatalf("want 200 after one retry, got %v %v", resp, err)
	}
	if len(clients) != 2 || !clients[0].closed.Load() {
		t.Fatalf("clients = %d, first closed = %v", len(clients), len(clients) > 0 && clients[0].closed.Load())
	}
	if clients[1].addr != "5.6.7.8:2" {
		t.Fatalf("retry used %s; after a stall it should move to the next address", clients[1].addr)
	}
	if dht.calls.Load() != 2 {
		t.Fatalf("DHT lookups = %d; the retry must look the address up again", dht.calls.Load())
	}
}

func TestPostIsNotRetriedAfterAStall(t *testing.T) {
	old := RLDPHeaderTimeout
	RLDPHeaderTimeout = 50 * time.Millisecond
	defer func() { RLDPHeaderTimeout = old }()

	tr := newTestTransport(okResolver(t, time.Millisecond), &fakeDHT{addrs: []string{"1.2.3.4:1"}})
	defer tr.stop()
	var dials atomic.Int32
	tr.dialRLDP = func(_ ed25519.PublicKey, addr, _ string) (RLDP, error) {
		dials.Add(1)
		return &fakeRLDP{addr: addr, stall: true}, nil
	}
	req, _ := http.NewRequest(http.MethodPost, "http://a.ton/form", nil)
	req.Host = "a.ton"
	req.Body = http.NoBody
	req.Method = http.MethodPost
	if _, err := tr.RoundTrip(req); !errors.Is(err, ErrStall) {
		t.Fatalf("want stall error, got %v", err)
	}
	if dials.Load() != 1 {
		t.Fatalf("dials = %d; a POST must not be sent twice", dials.Load())
	}
}

// dialWithDisconnect wires the real removeRLDP handler, as connectRLDP does.
func dialWithDisconnect(tr *Transport, mk func(addr string) *fakeRLDP, dials *atomic.Int32) func(ed25519.PublicKey, string, string) (RLDP, error) {
	return func(key ed25519.PublicKey, addr, host string) (RLDP, error) {
		dials.Add(1)
		c := mk(addr)
		c.SetOnDisconnect(tr.removeServer(hex.EncodeToString(key), c))
		return c, nil
	}
}

func TestASecondStallOnTheOldClientDoesNotKillTheNewOne(t *testing.T) {
	dht := &fakeDHT{addrs: []string{"1.2.3.4:1", "5.6.7.8:2"}}
	tr := newTestTransport(okResolver(t, time.Millisecond), dht)
	defer tr.stop()
	var dials atomic.Int32
	var mu sync.Mutex
	var made []*fakeRLDP
	tr.dialRLDP = dialWithDisconnect(tr, func(addr string) *fakeRLDP {
		mu.Lock()
		defer mu.Unlock()
		c := &fakeRLDP{addr: addr}
		made = append(made, c)
		return c
	}, &dials)

	first, err := tr.actorFor(context.Background(), "a.ton", nil)
	if err != nil {
		t.Fatal(err)
	}
	clientX := first.(*rldpInfo).ActiveClient
	// request A stalled on clientX and reconnected
	tr.dropClient("a.ton", first.(*rldpInfo), clientX)
	second, err := tr.actorFor(context.Background(), "a.ton", clientX)
	if err != nil {
		t.Fatal(err)
	}
	clientY := second.(*rldpInfo).ActiveClient
	// request B, also on clientX, stalls later: it must get clientY, not a third connection
	third, err := tr.actorFor(context.Background(), "a.ton", clientX)
	if err != nil {
		t.Fatal(err)
	}
	if third.(*rldpInfo).ActiveClient != clientY || dials.Load() != 2 {
		t.Fatalf("dials = %d; B's stall reconnected again and would close A's new client", dials.Load())
	}
	time.Sleep(20 * time.Millisecond) // let async disconnect handlers run
	if clientY.(*fakeRLDP).closed.Load() {
		t.Fatal("the live client was closed")
	}
}

func TestASlowPageOnALiveConnectionDoesNotDropIt(t *testing.T) {
	old := RLDPHeaderTimeout
	RLDPHeaderTimeout = 50 * time.Millisecond
	defer func() { RLDPHeaderTimeout = old }()

	tr := newTestTransport(okResolver(t, time.Millisecond), &fakeDHT{addrs: []string{"1.2.3.4:1"}})
	defer tr.stop()
	var dials atomic.Int32
	tr.dialRLDP = dialWithDisconnect(tr, func(addr string) *fakeRLDP { return &fakeRLDP{addr: addr} }, &dials)

	get := func() (*http.Response, error) {
		req, _ := http.NewRequest(http.MethodGet, "http://a.ton/", nil)
		req.Host = "a.ton"
		return tr.RoundTrip(req)
	}
	if _, err := get(); err != nil { // header arrives: lastHeaderAt set
		t.Fatal(err)
	}
	act, _ := tr.actorFor(context.Background(), "a.ton", nil)
	act.(*rldpInfo).ActiveClient.(*fakeRLDP).stall = true // this page is slow
	if _, err := get(); !errors.Is(err, ErrStall) {
		t.Fatalf("want stall, got %v", err)
	}
	if dials.Load() != 1 || act.(*rldpInfo).ActiveClient == nil {
		t.Fatalf("dials = %d; a connection that answered moments ago was dropped", dials.Load())
	}
}

func TestStallRetryWithTheRealDisconnectHandler(t *testing.T) {
	old := RLDPHeaderTimeout
	RLDPHeaderTimeout = 50 * time.Millisecond
	defer func() { RLDPHeaderTimeout = old }()

	tr := newTestTransport(okResolver(t, time.Millisecond), &fakeDHT{addrs: []string{"1.2.3.4:1", "5.6.7.8:2"}})
	defer tr.stop()
	var dials atomic.Int32
	tr.dialRLDP = dialWithDisconnect(tr, func(addr string) *fakeRLDP {
		return &fakeRLDP{addr: addr, stall: addr == "1.2.3.4:1"}
	}, &dials)
	req, _ := http.NewRequest(http.MethodGet, "http://a.ton/", nil)
	req.Host = "a.ton"
	resp, err := tr.RoundTrip(req)
	if err != nil || resp.StatusCode != 200 {
		t.Fatalf("want 200, got %v %v", resp, err)
	}
	time.Sleep(20 * time.Millisecond)
	act, _ := tr.actorFor(context.Background(), "a.ton", nil)
	if c := act.(*rldpInfo).ActiveClient; c == nil || c.(*fakeRLDP).addr != "5.6.7.8:2" {
		t.Fatal("the old client's disconnect handler removed the new client")
	}
}

// The 2026-09-27 finding: 23 of 71 directory sites share 6 servers. One client per server, or
// the sites on it take each other's replies away.
func TestSitesOnOneServerShareOneClient(t *testing.T) {
	tr := newTestTransport(okResolver(t, time.Millisecond), &fakeDHT{addrs: []string{"1.2.3.4:1"}})
	defer tr.stop()
	var dials atomic.Int32
	tr.dialRLDP = dialWithDisconnect(tr, func(addr string) *fakeRLDP { return &fakeRLDP{addr: addr} }, &dials)

	var wg sync.WaitGroup
	for _, h := range []string{"a.ton", "b.ton", "c.ton", "d.ton"} { // okResolver gives them all testID
		wg.Add(1)
		go func(h string) {
			defer wg.Done()
			if _, err := tr.actorFor(context.Background(), h, nil); err != nil {
				t.Error(err)
			}
		}(h)
	}
	wg.Wait()
	if dials.Load() != 1 {
		t.Fatalf("four sites on one server made %d clients; each would steal the others' replies", dials.Load())
	}
}

func TestAStallOnASharedServerReconnectsItsSitesOnce(t *testing.T) {
	old := RLDPHeaderTimeout
	RLDPHeaderTimeout = 50 * time.Millisecond
	defer func() { RLDPHeaderTimeout = old }()

	tr := newTestTransport(okResolver(t, time.Millisecond), &fakeDHT{addrs: []string{"1.2.3.4:1", "5.6.7.8:2"}})
	defer tr.stop()
	var dials atomic.Int32
	tr.dialRLDP = dialWithDisconnect(tr, func(addr string) *fakeRLDP {
		return &fakeRLDP{addr: addr, stall: addr == "1.2.3.4:1"}
	}, &dials)
	for _, h := range []string{"a.ton", "b.ton"} {
		if _, err := tr.actorFor(context.Background(), h, nil); err != nil {
			t.Fatal(err)
		}
	}
	req, _ := http.NewRequest(http.MethodGet, "http://a.ton/", nil)
	req.Host = "a.ton"
	if resp, err := tr.RoundTrip(req); err != nil || resp.StatusCode != 200 {
		t.Fatalf("a.ton: %v %v", resp, err)
	}
	time.Sleep(20 * time.Millisecond)
	req2, _ := http.NewRequest(http.MethodGet, "http://b.ton/", nil)
	req2.Host = "b.ton"
	if resp, err := tr.RoundTrip(req2); err != nil || resp.StatusCode != 200 {
		t.Fatalf("b.ton after its server reconnected: %v %v", resp, err)
	}
	if dials.Load() != 2 {
		t.Fatalf("dials = %d; want 2 (the dead client once, the new one shared)", dials.Load())
	}
}

// Each of a lookup's staggered attempts tells the resolver which one it is, so that a later
// attempt can ask at an older block than the one that is failing.
func TestEveryDNSAttemptSaysWhichOneItIs(t *testing.T) {
	if got := DNSAttempt(context.Background()); got != 0 {
		t.Fatalf("no attempt in the context reads as the first, got %d", got)
	}
	var mx sync.Mutex
	var seen []int
	tr := &Transport{resolver: resolverFunc(func(ctx context.Context, host string) (*dns.Domain, error) {
		mx.Lock()
		seen = append(seen, DNSAttempt(ctx))
		mx.Unlock()
		return nil, errors.New("lite server error, code 651")
	})}
	if _, err := tr.resolveDNS(context.Background(), "x.ton"); err == nil {
		t.Fatal("every attempt failed: an error")
	}
	sort.Ints(seen)
	if len(seen) != 3 || seen[0] != 0 || seen[1] != 1 || seen[2] != 2 {
		t.Fatalf("want attempts 0, 1, 2; got %v", seen)
	}
}

type resolverFunc func(ctx context.Context, host string) (*dns.Domain, error)

func (f resolverFunc) Resolve(ctx context.Context, host string) (*dns.Domain, error) {
	return f(ctx, host)
}
