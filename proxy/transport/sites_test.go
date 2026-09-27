package transport

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"errors"
	"fmt"
	"net"
	"net/http"
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

func (d *fakeDHT) StoreAddress(context.Context, address.List, time.Duration, ed25519.PrivateKey, int) (int, []byte, error) {
	return 0, nil, nil
}
func (d *fakeDHT) FindAddresses(ctx context.Context, _ []byte) (*address.List, ed25519.PublicKey, error) {
	d.calls.Add(1)
	l := &address.List{}
	for _, a := range d.addrs {
		host, port, _ := net.SplitHostPort(a)
		var p int32
		fmt.Sscan(port, &p)
		l.Addresses = append(l.Addresses, &address.UDP{IP: net.ParseIP(host), Port: p})
	}
	pub, _, _ := ed25519.GenerateKey(nil)
	return l, pub, nil
}
func (d *fakeDHT) Close() {}

// fakeRLDP answers the HTTP request header query, or stalls until the ctx ends.
type fakeRLDP struct {
	addr   string
	stall  bool
	closed atomic.Bool
}

func (f *fakeRLDP) Close()                                     { f.closed.Store(true) }
func (f *fakeRLDP) SetOnQuery(func([]byte, *rldp.Query) error) {}
func (f *fakeRLDP) SetOnDisconnect(func())                     {}
func (f *fakeRLDP) GetADNL() rldp.ADNL                         { return nil }
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
			if _, err := tr.actorFor(context.Background(), "a.ton", false); err != nil {
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
	if _, err := tr.actorFor(ctx, "a.ton", false); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("want deadline, got %v", err)
	}
	if d := time.Since(tm); d > 100*time.Millisecond {
		t.Fatalf("waiter held for %v; upstream waited on an uncancellable lock", d)
	}
	// the connect kept going in the background: the next request finds the site ready
	time.Sleep(400 * time.Millisecond)
	tm = time.Now()
	if _, err := tr.actorFor(context.Background(), "a.ton", false); err != nil {
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
	if _, err := tr.RoundTrip(req); !errors.Is(err, errStall) {
		t.Fatalf("want stall error, got %v", err)
	}
	if dials.Load() != 1 {
		t.Fatalf("dials = %d; a POST must not be sent twice", dials.Load())
	}
}
