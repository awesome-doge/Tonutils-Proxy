package transport

// ton2web fork: counters for the debug endpoint (/debug/vars). Everything the gateway's
// success rate depends on is counted here rather than inferred from log lines — upstream's
// retry loop wrote a dozen error lines per failed request, which made log counts useless.

import (
	"errors"
	"expvar"
	"os"
	"runtime"
	"time"

	"github.com/xssnick/tonutils-go/ton/dns"
)

type counters struct {
	requests      *expvar.Int
	rldpOK        *expvar.Int
	rldpStall     *expvar.Int
	rldpRetryOK   *expvar.Int
	rldpFail      *expvar.Int
	bagRequests   *expvar.Int
	bagStartOK    *expvar.Int
	bagStartFail  *expvar.Int
	connectOK     *expvar.Int
	serverReuse   *expvar.Int
	adnlReinit    *expvar.Int
	connectFail   *expvar.Int
	dnsCacheHit   *expvar.Int
	dnsCacheStale *expvar.Int
	dnsOK         *expvar.Int
	dnsFail       *expvar.Int
	dnsMs         *expvar.Map // histogram: bucket upper bound (ms) -> count
	dhtCacheHit   *expvar.Int
	dhtOK         *expvar.Int
	dhtFail       *expvar.Int
	headerMs      *expvar.Map // time to RLDP response header
	dhtMs         *expvar.Map // DHT address lookup
	waitMs        *expvar.Map // a request waiting for its site to be ready (0 when warm)
}

var metrics = counters{
	requests:      expvar.NewInt("proxy_requests"),
	rldpOK:        expvar.NewInt("rldp_ok"),
	rldpStall:     expvar.NewInt("rldp_stall"),
	rldpRetryOK:   expvar.NewInt("rldp_retry_ok"),
	rldpFail:      expvar.NewInt("rldp_fail"),
	bagRequests:   expvar.NewInt("bag_requests"),
	bagStartOK:    expvar.NewInt("bag_start_ok"),
	bagStartFail:  expvar.NewInt("bag_start_fail"),
	connectOK:     expvar.NewInt("connect_ok"),
	serverReuse:   expvar.NewInt("server_reuse"), // a site joined a server that already had a client
	adnlReinit:    expvar.NewInt("adnl_reinit"),
	connectFail:   expvar.NewInt("connect_fail"),
	dnsCacheHit:   expvar.NewInt("dns_cache_hit"),
	dnsCacheStale: expvar.NewInt("dns_cache_stale"),
	dnsOK:         expvar.NewInt("dns_ok"),
	dnsFail:       expvar.NewInt("dns_fail"),
	dnsMs:         expvar.NewMap("dns_ms"),
	dhtCacheHit:   expvar.NewInt("dht_cache_hit"),
	dhtOK:         expvar.NewInt("dht_ok"),
	dhtFail:       expvar.NewInt("dht_fail"),
	headerMs:      expvar.NewMap("rldp_header_ms"),
	dhtMs:         expvar.NewMap("dht_ms"),
	waitMs:        expvar.NewMap("site_wait_ms"),
}

func init() {
	// Open file descriptors and goroutines: on 2026-09-27 upstream held ~2,200 sockets in the
	// CLOSED state after 38 days (likely tonutils-go liteclient not closing a TCP connection when
	// the handshake fails, retried every 3 s). Watch the trend here rather than guess.
	expvar.Publish("open_fds", expvar.Func(func() any {
		entries, err := os.ReadDir("/proc/self/fd")
		if err != nil {
			return -1
		}
		return len(entries)
	}))
	expvar.Publish("goroutines", expvar.Func(func() any { return runtime.NumGoroutine() }))
}

var buckets = []int64{10, 100, 250, 500, 1000, 2000, 4000, 8000, 16000}

func bucket(d time.Duration) string {
	ms := d.Milliseconds()
	for _, b := range buckets {
		if ms <= b {
			return "le_" + itoa(b)
		}
	}
	return "gt_16000"
}

func itoa(v int64) string {
	if v == 0 {
		return "0"
	}
	var b [20]byte
	i := len(b)
	for v > 0 {
		i--
		b[i] = byte('0' + v%10)
		v /= 10
	}
	return string(b[i:])
}

func (c *counters) observeDNS(d time.Duration, err error) {
	if err != nil && !errors.Is(err, dns.ErrNoSuchRecord) { // "no such record" is an answer
		c.dnsFail.Add(1)
		return
	}
	c.dnsOK.Add(1)
	c.dnsMs.Add(bucket(d), 1)
}
