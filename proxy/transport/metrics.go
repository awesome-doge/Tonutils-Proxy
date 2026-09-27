package transport

// ton2web fork: counters for the debug endpoint (/debug/vars). Everything the gateway's
// success rate depends on is counted here rather than inferred from log lines — upstream's
// retry loop wrote a dozen error lines per failed request, which made log counts useless.

import (
	"errors"
	"expvar"
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
	connectOK     *expvar.Int
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
}

var metrics = counters{
	requests:      expvar.NewInt("proxy_requests"),
	rldpOK:        expvar.NewInt("rldp_ok"),
	rldpStall:     expvar.NewInt("rldp_stall"),
	rldpRetryOK:   expvar.NewInt("rldp_retry_ok"),
	rldpFail:      expvar.NewInt("rldp_fail"),
	bagRequests:   expvar.NewInt("bag_requests"),
	connectOK:     expvar.NewInt("connect_ok"),
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
}

var buckets = []int64{250, 500, 1000, 2000, 4000, 8000, 16000}

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
