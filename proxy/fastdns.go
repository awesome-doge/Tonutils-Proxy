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

import (
	"bytes"
	"context"
	"expvar"
	"strings"
	"sync/atomic"
	"time"

	"github.com/rs/zerolog/log"
	"github.com/xssnick/tonutils-go/address"
	"github.com/xssnick/tonutils-go/ton"
	"github.com/xssnick/tonutils-go/ton/dns"
)

var dnsPath = expvar.NewMap("dns_path") // which path each lookup took

// The .ton DNS collection (TEP-81), a fixed on-chain address.
const tonCollection = "EQC3dNlesgVD8YbAazcauIrXBPfiVhMMr5YYk2in0Mtsz0Bz"

// Blocks older than this are not used for a lookup (DNS records rarely change within a minute).
const blockMaxAge = 60 * time.Second

type cachedBlock struct {
	b  *ton.BlockIDExt
	at time.Time
}

type fastResolver struct {
	api        ton.APIClientWrapped
	standard   *dns.Client
	collection *dns.Client // resolves "name" against the .ton collection
	block      atomic.Pointer[cachedBlock]
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
	for {
		c, cancel := context.WithTimeout(ctx, 10*time.Second)
		b, err := r.api.GetMasterchainInfo(c)
		cancel()
		if err == nil {
			r.block.Store(&cachedBlock{b: b, at: time.Now()})
		}
		select {
		case <-ctx.Done():
			return
		case <-time.After(3 * time.Second):
		}
	}
}

func (r *fastResolver) freshBlock() *ton.BlockIDExt {
	cb := r.block.Load()
	if cb == nil || time.Since(cb.at) > blockMaxAge {
		return nil
	}
	return cb.b
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
		b := r.freshBlock()
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
	b := r.freshBlock()
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
