package transport

// ton2web fork: how a request finds its site.
//
// Upstream held a per-site mutex across DNS resolve + DHT lookup + RLDP connect (and, for bags,
// torrent start), retried DNS in three goroutines with no backoff until the caller gave up, and
// re-resolved every site that had been idle for 90 s. Under load that produced minutes-long queues
// behind one lock, thousands of error lines per failing request, and a cold lookup on almost
// every visit. Here:
//
//   - DNS results are cached (fresh 5 min, usable 24 h with a background refresh; "no such record"
//     for 2 min). A lookup is one flight per host with staggered, bounded attempts.
//   - Connecting a site is one background flight per host. Nobody holds a lock across network I/O;
//     waiters give up when their own request does, and the flight finishes for the next request.
//   - A request that gets no response header within RLDPHeaderTimeout drops the connection,
//     looks the address up again in the DHT and retries once (GET/HEAD only).

import (
	"context"
	"crypto/ed25519"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/rs/zerolog/log"
	"github.com/xssnick/tonutils-go/adnl"
	"github.com/xssnick/tonutils-go/adnl/address"
	"github.com/xssnick/tonutils-go/ton/dns"
	"github.com/xssnick/tonutils-storage/storage"
)

// Tunables (set from the CLI flags before the transport starts).
var (
	DNSFreshFor        = 5 * time.Minute
	DNSUsableFor       = 24 * time.Hour
	DNSNotFoundFor     = 2 * time.Minute
	DNSLookupBudget    = 12 * time.Second
	DHTFreshFor        = 30 * time.Minute
	DHTUsableFor       = 24 * time.Hour
	ConnectBudget      = 30 * time.Second
	BagStartBudget     = 12 * time.Second
	RLDPHeaderTimeout  = 10 * time.Second
	SiteIdleEvict      = 15 * time.Minute
	BagIdleStop        = 5 * time.Minute
	StorageUpload      = true
	dnsAttemptStarts   = []time.Duration{0, 1500 * time.Millisecond, 3500 * time.Millisecond}
	dnsAttemptTimeouts = []time.Duration{4 * time.Second, 5 * time.Second, 6 * time.Second}
)

// ErrStall: connected, but no response header within RLDPHeaderTimeout.
var ErrStall = errors.New("rldp: no response header in time")

// A client that produced a header for another request this recently is a slow endpoint, not a
// dead peer: the stalled request fails, the connection is kept.
var recentHeaderGrace = 5 * time.Second

// flight is one in-progress operation that any number of requests may wait on.
type flight struct {
	done    chan struct{}
	started time.Time
	err     error
}

func newFlight() *flight { return &flight{done: make(chan struct{}), started: time.Now()} }

// wait returns the flight's error, or the caller's ctx error if the caller gives up first.
func (f *flight) wait(ctx context.Context) error {
	select {
	case <-f.done:
		return f.err
	case <-ctx.Done():
		return ctx.Err()
	}
}

// A flight that has run far past its budget no longer blocks a fresh attempt.
func (f *flight) abandoned(budget time.Duration) bool { return time.Since(f.started) > 2*budget }

// ---- DNS ----

type dnsRecord struct {
	id        []byte
	inStorage bool
	notFound  bool
	at        time.Time
}

type dnsCache struct {
	mx      sync.Mutex
	entries map[string]*dnsRecord
	flights map[string]*flight
}

func newDNSCache() *dnsCache {
	return &dnsCache{entries: map[string]*dnsRecord{}, flights: map[string]*flight{}}
}

// lookup returns the site record for a .ton/.t.me name, from cache when possible.
func (t *Transport) lookup(ctx context.Context, host string) (*dnsRecord, error) {
	c := t.dns
	for {
		c.mx.Lock()
		e := c.entries[host]
		if e != nil {
			age := time.Since(e.at)
			if e.notFound && age < DNSNotFoundFor {
				c.mx.Unlock()
				metrics.dnsCacheHit.Add(1)
				return nil, fmt.Errorf("domain %s resolve err: %w", host, dns.ErrNoSuchRecord)
			}
			if !e.notFound && age < DNSUsableFor {
				if age >= DNSFreshFor && c.flights[host] == nil {
					t.startDNSFlightLocked(host) // refresh in the background, answer from cache now
					metrics.dnsCacheStale.Add(1)
				} else {
					metrics.dnsCacheHit.Add(1)
				}
				c.mx.Unlock()
				return e, nil
			}
		}
		f := c.flights[host]
		if f == nil || f.abandoned(DNSLookupBudget) {
			f = t.startDNSFlightLocked(host)
		}
		c.mx.Unlock()

		if err := f.wait(ctx); err != nil {
			return nil, err
		}
		// loop: the flight stored its result (or a not-found marker) in the cache
		c.mx.Lock()
		e = c.entries[host]
		c.mx.Unlock()
		if e == nil {
			return nil, fmt.Errorf("failed to resolve domain %s in ton dns", host)
		}
	}
}

// startDNSFlightLocked must be called with t.dns.mx held.
func (t *Transport) startDNSFlightLocked(host string) *flight {
	f := newFlight()
	t.dns.flights[host] = f
	go func() {
		ctx, cancel := context.WithTimeout(t.globalCtx, DNSLookupBudget)
		defer cancel()
		tm := time.Now()
		domain, err := t.resolveDNS(ctx, host)
		metrics.observeDNS(time.Since(tm), err)

		t.dns.mx.Lock()
		switch {
		case err == nil:
			id, inStorage := domain.GetSiteRecord()
			t.dns.entries[host] = &dnsRecord{id: id, inStorage: inStorage, at: time.Now()}
		case errors.Is(err, dns.ErrNoSuchRecord):
			t.dns.entries[host] = &dnsRecord{notFound: true, at: time.Now()}
		default:
			// keep a usable stale entry if there is one; the error only reaches waiters
			log.Warn().Err(err).Str("domain", host).Dur("took", time.Since(tm)).Msg("resolve failed")
			f.err = err
		}
		delete(t.dns.flights, host)
		t.dns.mx.Unlock()
		close(f.done)
	}()
	return f
}

// resolveDNS runs up to three staggered attempts (a hedge against one slow liteserver); the
// first answer wins and cancels the rest. An attempt that fails early starts the next one at once.
func (t *Transport) resolveDNS(ctx context.Context, host string) (*dns.Domain, error) {
	type result struct {
		d   *dns.Domain
		err error
	}
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	n := len(dnsAttemptStarts)
	res := make(chan result, n)
	launched, received := 0, 0
	launch := func() {
		i := launched
		launched++
		go func() {
			actx, acancel := context.WithTimeout(ctx, dnsAttemptTimeouts[i])
			d, err := t.resolver.Resolve(actx, host)
			acancel()
			res <- result{d, err}
		}()
	}

	launch()
	timer := time.NewTimer(dnsAttemptStarts[1])
	defer timer.Stop()
	armNext := func() {
		if launched < n {
			timer.Reset(dnsAttemptStarts[launched] - dnsAttemptStarts[launched-1])
		}
	}

	var lastErr error
	for received < n {
		select {
		case r := <-res:
			received++
			if r.err == nil {
				return r.d, nil
			}
			if errors.Is(r.err, dns.ErrNoSuchRecord) {
				return nil, r.err
			}
			lastErr = r.err
			if received == launched && launched < n {
				if !timer.Stop() {
					select {
					case <-timer.C:
					default:
					}
				}
				launch()
				armNext()
			}
		case <-timer.C:
			if launched < n {
				launch()
				armNext()
			}
		case <-ctx.Done():
			if lastErr == nil {
				lastErr = ctx.Err()
			}
			return nil, fmt.Errorf("failed to resolve domain %s in ton dns: %w", host, lastErr)
		}
	}
	return nil, fmt.Errorf("failed to resolve domain %s in ton dns: %w", host, lastErr)
}

// ---- DHT address cache ----

type dhtRecord struct {
	list       *address.List
	key        ed25519.PublicKey
	at         time.Time
	refreshing bool
}

// findAddresses returns a server's addresses from the DHT. Measured on 2026-09-27, most lookups
// take 0.25-1 s but some take 4-16 s, so results are kept: fresh for DHTFreshFor, then still used
// (with a background refresh) up to DHTUsableFor. A stall forces a fresh lookup (fresh=true).
func (t *Transport) findAddresses(ctx context.Context, id []byte, fresh bool) (*address.List, ed25519.PublicKey, error) {
	k := hex.EncodeToString(id)
	if !fresh {
		t.mx.Lock()
		r := t.dhtCache[k]
		if r != nil {
			age := time.Since(r.at)
			if age < DHTUsableFor {
				if age >= DHTFreshFor && !r.refreshing {
					r.refreshing = true
					go func() {
						c, cancel := context.WithTimeout(t.globalCtx, ConnectBudget)
						defer cancel()
						_, _, _ = t.lookupDHT(c, id, k)
						t.mx.Lock()
						if cur := t.dhtCache[k]; cur != nil {
							cur.refreshing = false
						}
						t.mx.Unlock()
					}()
				}
				t.mx.Unlock()
				metrics.dhtCacheHit.Add(1)
				return r.list, r.key, nil
			}
		}
		t.mx.Unlock()
	}
	return t.lookupDHT(ctx, id, k)
}

func (t *Transport) lookupDHT(ctx context.Context, id []byte, k string) (*address.List, ed25519.PublicKey, error) {
	tm := time.Now()
	list, key, err := t.dht.FindAddresses(ctx, id)
	metrics.dhtMs.Add(bucket(time.Since(tm)), 1)
	if err != nil {
		metrics.dhtFail.Add(1)
		return nil, nil, err
	}
	metrics.dhtOK.Add(1)
	t.mx.Lock()
	t.dhtCache[k] = &dhtRecord{list: list, key: key, at: time.Now()}
	t.mx.Unlock()
	return list, key, nil
}

func (t *Transport) forgetAddresses(id []byte) {
	t.mx.Lock()
	delete(t.dhtCache, hex.EncodeToString(id))
	t.mx.Unlock()
}

// ---- one client per server ----
//
// Many .ton sites share one server (same ADNL key): on 2026-09-27, 23 of the 71 directory sites
// were on 6 servers. The gateway keeps ONE peer per key, and every RLDP client made on a peer
// takes over its message handler. Upstream made a client per SITE, so on a shared server only
// the most recently connected site got answers; the others hung until a 15 s timeout (and when
// one was closed, the peer closed under all of them). Here a server has one client, shared by
// its sites; the request's Host header says which site is meant.

type serverClient struct {
	rl           RLDP
	key          string
	lastHeaderAt int64 // unix nanos of the last response header, any site
	lastUsed     int64 // unix seconds
}

// serverFor returns the server's shared client, making it on first use.
func (t *Transport) serverFor(pubKey ed25519.PublicKey, addr, host string) (*serverClient, error) {
	k := hex.EncodeToString(pubKey)
	t.mx.Lock()
	defer t.mx.Unlock()
	if sc := t.servers[k]; sc != nil {
		metrics.serverReuse.Add(1)
		return sc, nil
	}
	// dialRLDP is local (registers the peer, no network), so holding t.mx is cheap and makes
	// sure two sites on one server never create two clients.
	rl, err := t.dialRLDP(pubKey, addr, host)
	if err != nil {
		return nil, err
	}
	sc := &serverClient{rl: rl, key: k, lastUsed: time.Now().Unix()}
	t.servers[k] = sc
	return sc, nil
}

func (t *Transport) closeIdleServers(now int64) {
	var idle []*serverClient
	t.mx.Lock()
	for k, sc := range t.servers {
		if now-atomic.LoadInt64(&sc.lastUsed) > int64(SiteIdleEvict.Seconds()) {
			delete(t.servers, k)
			idle = append(idle, sc)
		}
	}
	t.mx.Unlock()
	for _, sc := range idle {
		t.clearClient(sc.rl)
		sc.rl.Close()
	}
}

// ---- connecting a site ----

// site returns (creating if needed) the state for a host.
func (t *Transport) site(host string) *siteInfo {
	t.mx.Lock()
	defer t.mx.Unlock()
	s := t.activeSites[host]
	if s == nil {
		s = &siteInfo{LastUsed: time.Now().Unix()}
		t.activeSites[host] = s
	}
	return s
}

// actorFor returns a usable actor for the host, connecting in a background flight if needed.
// stalled is the client a request just gave up on: if the site's current client is a different
// live one (another request already reconnected), that one is used; otherwise a new DHT lookup
// and a new connection are made.
func (t *Transport) actorFor(ctx context.Context, host string, stalled RLDP) (any, error) {
	s := t.site(host)
	fresh := stalled != nil
	for {
		s.mx.Lock()
		now := time.Now().Unix()
		prevUsed := atomic.SwapInt64(&s.LastUsed, now)
		if fresh {
			if act, ok := s.Actor.(*rldpInfo); ok && act.ActiveClient != nil && act.ActiveClient != stalled {
				fresh = false // someone reconnected since this request's client stalled
			}
		}
		if !fresh {
			switch act := s.Actor.(type) {
			case *bagInfo:
				s.mx.Unlock()
				return act, nil
			case *rldpInfo:
				if act.ActiveClient != nil {
					// Re-establish an idle ADNL channel on next use (as upstream) — but judged by the
					// SERVER's shared peer: resetting it because one of its sites was idle would cut
					// off transfers other sites on the same server have in flight.
					idleFor := now - prevUsed
					if act.server != nil {
						idleFor = now - atomic.SwapInt64(&act.server.lastUsed, now)
					}
					if idleFor > 30 {
						// as upstream: an idle ADNL channel is re-established on next use (local, cheap)
						if p, ok := act.ActiveClient.GetADNL().(adnl.Peer); ok {
							metrics.adnlReinit.Add(1)
							p.Reinit()
						}
					}
					s.mx.Unlock()
					return act, nil
				}
			}
		}
		f := s.connecting
		if f == nil || f.abandoned(ConnectBudget) {
			f = newFlight()
			s.connecting = f
			go t.connectFlight(s, host, f, fresh)
		}
		s.mx.Unlock()

		if err := f.wait(ctx); err != nil {
			return nil, err
		}
		fresh = false // the flight replaced the actor; use it
	}
}

func (t *Transport) connectFlight(s *siteInfo, host string, f *flight, fresh bool) {
	ctx, cancel := context.WithTimeout(t.globalCtx, ConnectBudget)
	defer cancel()
	tm := time.Now()

	var old any
	s.mx.Lock()
	old = s.Actor
	s.mx.Unlock()

	actor, err := t.connect(ctx, host, old, fresh)
	if err != nil {
		metrics.connectFail.Add(1)
		log.Warn().Err(err).Str("host", host).Dur("took", time.Since(tm)).Msg("connect failed")
	} else {
		metrics.connectOK.Add(1)
	}

	s.mx.Lock()
	if err == nil && s.connecting != f {
		// superseded after running past its budget: a newer flight owns the site; do not
		// install over it, and release what this one built
		s.mx.Unlock()
		t.teardown(actor)
		f.err = errors.New("connect superseded")
		close(f.done)
		return
	}
	if err == nil {
		// the previous client is NOT closed here: it may be the server's shared client
		s.Actor = actor
		atomic.StoreInt64(&s.LastSuccess, time.Now().Unix())
	}
	f.err = err
	if s.connecting == f {
		s.connecting = nil
	}
	s.mx.Unlock()
	close(f.done)
}

// connect resolves the host and opens an RLDP client (or starts its storage bag).
func (t *Transport) connect(ctx context.Context, host string, old any, fresh bool) (any, error) {
	var id []byte
	var inStorage bool
	var err error

	switch {
	case strings.HasSuffix(host, ".adnl"):
		if id, err = ParseADNLAddress(host[:len(host)-5]); err != nil {
			return nil, fmt.Errorf("failed to parse adnl address %s, err: %w", host, err)
		}
	case strings.HasSuffix(host, ".bag"):
		if id, err = hex.DecodeString(host[:len(host)-4]); err != nil {
			return nil, fmt.Errorf("failed to parse bag id %s, err: %w", host, err)
		}
		inStorage = true
	default:
		rec, err := t.lookup(ctx, host)
		if err != nil {
			return nil, err
		}
		id, inStorage = rec.id, rec.inStorage
	}

	if inStorage {
		return t.startBag(ctx, host, id)
	}

	list, pubKey, err := t.findAddresses(ctx, id, fresh)
	if err != nil {
		return nil, fmt.Errorf("failed to find address of %s (%s) in DHT, err: %w", host, hex.EncodeToString(id), err)
	}
	if len(list.Addresses) == 0 {
		return nil, fmt.Errorf("failed to find address of %s (%s) in DHT, no addresses in record", host, hex.EncodeToString(id))
	}

	// After a stall, start from the address after the one that stalled.
	start := 0
	if prev, ok := old.(*rldpInfo); ok && fresh && len(list.Addresses) > 1 {
		for i, v := range list.Addresses {
			if fmt.Sprintf("%s:%d", v.IP.String(), v.Port) == prev.Addr {
				start = (i + 1) % len(list.Addresses)
			}
		}
	}

	var tried []string
	for i := 0; i < len(list.Addresses); i++ {
		v := list.Addresses[(start+i)%len(list.Addresses)]
		addr := fmt.Sprintf("%s:%d", v.IP.String(), v.Port)
		sc, cerr := t.serverFor(pubKey, addr, host)
		if cerr != nil {
			tried = append(tried, addr)
			err = cerr
			continue
		}
		return &rldpInfo{ActiveClient: sc.rl, server: sc, ID: pubKey, NodeID: id, Addr: addr}, nil
	}
	return nil, fmt.Errorf("failed to connect to rldp servers %s of host %s, err: %w", tried, host, err)
}

func (t *Transport) startBag(ctx context.Context, host string, id []byte) (any, error) {
	torrent := storage.NewTorrent("", t.store, t.storageConnector)
	torrent.BagID = id
	_ = t.store.SetTorrent(torrent)

	if err := torrent.Start(StorageUpload, false, false); err != nil {
		return nil, fmt.Errorf("failed to start bag %s, err: %w", host, err)
	}

	// CreateDownloader polls every 10 ms until it finds a storage node for the bag or its context
	// ends (tonutils-storage client.go). Upstream passed the process-lifetime context, so every bag
	// nobody seeds left a goroutine waking 100 times a second, forever — a weekly scan probes
	// hundreds of such bags. Here the search has its own context: BagStartBudget, then cancelled.
	// On success the downloader keeps it (it lives as long as the bag; cancel runs when it stops).
	dctx, cancel := context.WithCancel(t.globalCtx)
	type result struct {
		d   storage.TorrentDownloader
		err error
	}
	ch := make(chan result, 1)
	go func() {
		d, err := t.storageConnector.CreateDownloader(dctx, torrent)
		ch <- result{d, err}
	}()
	fail := func(err error) (any, error) {
		cancel()
		torrent.Stop()
		t.store.RemoveTorrent(id)
		metrics.bagStartFail.Add(1)
		return nil, err
	}
	budget := time.NewTimer(BagStartBudget)
	defer budget.Stop()
	select {
	case r := <-ch:
		if r.err != nil {
			return fail(fmt.Errorf("failed to create downloader for storage bag of %s, err: %w", host, r.err))
		}
		log.Info().Str("bag_id", hex.EncodeToString(id)).Str("host", host).Msg("bag started")
		metrics.bagStartOK.Add(1)
		return &bagInfo{torrent: torrent, downloader: r.d, cancel: cancel}, nil
	case <-budget.C:
	case <-ctx.Done():
	}
	cancel() // stops the polling; CreateDownloader returns an error
	go func() {
		if r := <-ch; r.d != nil {
			r.d.Close()
		}
	}()
	return fail(fmt.Errorf("storage bag of %s: no downloader in time: %w", host, context.DeadlineExceeded))
}

// teardown releases an actor that will not be used.
func (t *Transport) teardown(actor any) {
	switch a := actor.(type) {
	case *rldpInfo:
		// shared with the server's other sites: nothing to release
	case *bagInfo:
		t.stopBag(a)
	}
}

// stopBag releases everything a started bag holds.
func (t *Transport) stopBag(a *bagInfo) {
	a.downloader.Close()
	a.torrent.Stop()
	if a.cancel != nil {
		a.cancel()
	}
	t.store.RemoveTorrent(a.torrent.BagID)
}

// dropClient forgets a server client that stalled: removed from the map at once (so no request
// can pick up the dead one), detached from every site on that server, then closed.
func (t *Transport) dropClient(host string, act *rldpInfo, client RLDP) {
	if act.server != nil {
		t.mx.Lock()
		if sc := t.servers[act.server.key]; sc != nil && sc.rl == client {
			delete(t.servers, act.server.key)
		}
		t.mx.Unlock()
	}
	t.clearClient(client)
	client.Close()
	t.forgetAddresses(act.NodeID)
}
