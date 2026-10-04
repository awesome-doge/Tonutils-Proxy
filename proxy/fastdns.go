package proxy

// ton2web fork: a faster TON DNS resolver.
//
// Resolving "name.ton" with dns.Client costs four sequential liteserver round trips:
// masterchain info -> root contract ("ton" -> .ton collection) -> collection ("name" -> item)
// -> item (records). From Taiwan to the public liteservers (Finland/Germany) that is about
// 1.1 s, and the masterchain step sits behind a lock shared by every lookup.
//
// Here the masterchain block is refreshed in the background (a lookup never waits for it), and
// the .ton collection address is known, so a lookup is two round trips: collection, item.
// The fast path is only used after a startup self-check resolves sample names both ways and gets
// the same site record; otherwise (and for anything else, e.g. .t.me) the standard path is used.
//
// Which block a lookup asks at (2026-10-04). It used to be the newest one. A liteserver knows
// the newest masterchain block before its shard client has applied the basechain block under
// it, and the .ton collection lives in the basechain — so most of them answered error 651
// ("block is not in db ... possibly out of sync"), and all three attempts of a lookup asked at
// that same block. Measured that day on the 12 public liteservers that accept connections
// (18 are listed), one name, eleven rounds:
//
//	block asked for    newest   10 s   20 s   30 s   45 s   60 s   90 s and older
//	answered           30%      58%    69%    66%    94%    98%    100% (132 of 132)
//
// and in this proxy: 191 of 563 lookups failed in the 25 minutes after a restart, 3,654 during
// the weekly scan's hour — one probe in three never reached the site it was meant for.
// A lookup therefore asks at a block that has had time to settle: the newest one at least
// settledAges[0] old, and an older one on each further attempt. A record changed on chain is
// seen that much later; the DNS cache (fresh for five minutes) already hides more than that.

import (
	"bytes"
	"context"
	"expvar"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/rs/zerolog/log"
	"github.com/xssnick/tonutils-go/address"
	"github.com/xssnick/tonutils-go/ton"
	"github.com/xssnick/tonutils-go/ton/dns"
	"github.com/xssnick/tonutils-proxy/proxy/transport"
)

var dnsPath = expvar.NewMap("dns_path") // which path each lookup took

// The .ton DNS collection (TEP-81), a fixed on-chain address.
const tonCollection = "EQC3dNlesgVD8YbAazcauIrXBPfiVhMMr5YYk2in0Mtsz0Bz"

// How old the block of a lookup's first, second and third attempt is, at least.
var settledAges = []time.Duration{90 * time.Second, 180 * time.Second, 300 * time.Second}

// Blocks are kept this long. When the newest one seen is older than this the refresh has
// stopped working, and lookups go back to the standard resolver, which asks for a block itself.
const blockKeepFor = 10 * time.Minute

// After a start there is no history yet, so three older blocks are looked up by number and
// filed under the age they have at the block rate measured 2026-10-04 (8,676 masterchain
// blocks in 59 minutes: 2.45 a second). A different rate only shifts those first minutes.
const seedBlocksPerAge = 250 // about 102 s at that rate

var seedAges = []time.Duration{300 * time.Second, 200 * time.Second, 100 * time.Second}

type cachedBlock struct {
	b  *ton.BlockIDExt
	at time.Time // when it was the newest block (for a seeded block: an estimate)
}

// blockHistory holds the masterchain blocks seen lately, oldest first.
type blockHistory struct {
	mx     sync.Mutex
	blocks []cachedBlock
}

func (h *blockHistory) add(b *ton.BlockIDExt, at time.Time) {
	h.mx.Lock()
	defer h.mx.Unlock()
	if n := len(h.blocks); n > 0 && h.blocks[n-1].b.SeqNo >= b.SeqNo {
		return // the same block again, or an answer from a liteserver that is behind
	}
	h.blocks = append(h.blocks, cachedBlock{b: b, at: at})
	drop := 0
	for drop < len(h.blocks)-1 && at.Sub(h.blocks[drop].at) > blockKeepFor {
		drop++
	}
	h.blocks = h.blocks[drop:]
}

// seed files older blocks in front of what is there; they must be given oldest first.
func (h *blockHistory) seed(older []cachedBlock) {
	h.mx.Lock()
	defer h.mx.Unlock()
	var keep []cachedBlock
	for _, o := range older {
		if len(h.blocks) == 0 || (o.b.SeqNo < h.blocks[0].b.SeqNo && o.at.Before(h.blocks[0].at)) {
			keep = append(keep, o)
		}
	}
	h.blocks = append(keep, h.blocks...)
}

// pick returns the newest block that is at least minAge old. While nothing is that old yet
// (the first moments after a start) it is the oldest block there is. Nil when there is no
// block, or when the newest one is older than blockKeepFor (the refresh has stopped).
func (h *blockHistory) pick(minAge time.Duration, now time.Time) *ton.BlockIDExt {
	h.mx.Lock()
	defer h.mx.Unlock()
	n := len(h.blocks)
	if n == 0 || now.Sub(h.blocks[n-1].at) > blockKeepFor {
		return nil
	}
	for i := n - 1; i >= 0; i-- {
		if now.Sub(h.blocks[i].at) >= minAge {
			return h.blocks[i].b
		}
	}
	return h.blocks[0].b
}

type fastResolver struct {
	api        ton.APIClientWrapped
	standard   *dns.Client
	collection *dns.Client // resolves "name" against the .ton collection
	history    blockHistory
	enabled    atomic.Bool
}

func newFastResolver(ctx context.Context, api ton.APIClientWrapped, standard *dns.Client) *fastResolver {
	r := &fastResolver{
		api:        api,
		standard:   standard,
		collection: dns.NewDNSClient(api, address.MustParseAddr(tonCollection)),
	}
	go r.refreshBlocks(ctx)
	go r.selfCheck(ctx)
	return r
}

func (r *fastResolver) refreshBlocks(ctx context.Context) {
	seeded := false
	for {
		c, cancel := context.WithTimeout(ctx, 10*time.Second)
		b, err := r.api.GetMasterchainInfo(c)
		cancel()
		if err == nil {
			now := time.Now()
			r.history.add(b, now)
			if !seeded {
				seeded = true
				go r.seedHistory(ctx, b, now)
			}
		}
		select {
		case <-ctx.Done():
			return
		case <-time.After(3 * time.Second):
		}
	}
}

// seedHistory looks up three blocks behind `tip` so that the first lookups after a start have
// a settled block to ask at. A failure only means those lookups ask at the oldest block seen.
func (r *fastResolver) seedHistory(ctx context.Context, tip *ton.BlockIDExt, now time.Time) {
	var older []cachedBlock
	for _, age := range seedAges {
		back := uint32(age/seedAges[len(seedAges)-1]) * seedBlocksPerAge
		if tip.SeqNo <= back {
			continue
		}
		c, cancel := context.WithTimeout(ctx, 10*time.Second)
		b, err := r.api.LookupBlock(c, tip.Workchain, tip.Shard, tip.SeqNo-back)
		cancel()
		if err != nil {
			log.Warn().Err(err).Uint32("back", back).Msg("could not look up an older block for DNS lookups")
			continue
		}
		older = append(older, cachedBlock{b: b, at: now.Add(-age)})
	}
	r.history.seed(older)
	log.Info().Int("blocks", len(older)).Msg("DNS lookups ask at a settled block")
}

// settledBlock is the block attempt number `attempt` (0 = the first) of a lookup asks at.
func (r *fastResolver) settledBlock(attempt int) *ton.BlockIDExt {
	if attempt < 0 {
		attempt = 0
	}
	if attempt >= len(settledAges) {
		attempt = len(settledAges) - 1
	}
	return r.history.pick(settledAges[attempt], time.Now())
}

// selfCheck enables the fast path once sample names resolve to the same site record both ways.
func (r *fastResolver) selfCheck(ctx context.Context) {
	samples := []string{"foundation.ton", "antonlukin.ton", "krasovsky.ton"}
	for attempt := 0; attempt < 20; attempt++ {
		select {
		case <-ctx.Done():
			return
		case <-time.After(5 * time.Second):
		}
		b := r.settledBlock(0)
		if b == nil {
			continue
		}
		ok := true
		for _, name := range samples {
			c, cancel := context.WithTimeout(ctx, 15*time.Second)
			std, err1 := r.standard.ResolveAtBlock(c, name, b)
			fast, err2 := r.collection.ResolveAtBlock(c, strings.TrimSuffix(name, ".ton"), b)
			cancel()
			if err1 != nil || err2 != nil {
				ok = false
				break
			}
			id1, st1 := std.GetSiteRecord()
			id2, st2 := fast.GetSiteRecord()
			if !bytes.Equal(id1, id2) || st1 != st2 {
				log.Error().Str("name", name).Msg("fast DNS self-check: records differ; fast path stays off")
				return
			}
		}
		if ok {
			r.enabled.Store(true)
			log.Info().Msg("fast DNS path enabled (self-check passed)")
			return
		}
	}
	log.Warn().Msg("fast DNS self-check did not complete; using the standard resolver")
}

func (r *fastResolver) Resolve(ctx context.Context, domain string) (*dns.Domain, error) {
	b := r.settledBlock(transport.DNSAttempt(ctx))
	if b == nil {
		dnsPath.Add("standard", 1)
		return r.standard.Resolve(ctx, domain)
	}
	if r.enabled.Load() && strings.HasSuffix(domain, ".ton") && strings.Count(domain, ".") >= 1 {
		dnsPath.Add("fast", 1)
		return r.collection.ResolveAtBlock(ctx, strings.TrimSuffix(domain, ".ton"), b)
	}
	dnsPath.Add("block-cached", 1) // skips only the masterchain step
	return r.standard.ResolveAtBlock(ctx, domain, b)
}
