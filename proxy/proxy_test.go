package proxy

import (
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"

	"github.com/xssnick/tonutils-go/ton/dns"
	"github.com/xssnick/tonutils-proxy/proxy/transport"
)

type failingRT struct{ err error }

func (f failingRT) RoundTrip(*http.Request) (*http.Response, error) { return nil, f.err }

// The gateway's bridge decides "the site failed" vs "we failed" from this header.
func TestServeHTTPNamesTheFailure(t *testing.T) {
	cases := []struct {
		err  error
		want string
	}{
		{fmt.Errorf("failed to request rldp-http site: %w", transport.ErrStall), "stall"},
		{fmt.Errorf("failed to connect to site: domain x resolve err: %w", dns.ErrNoSuchRecord), "no-record"},
		{errors.New("failed to connect to site: failed to resolve domain a.ton in ton dns: deadline exceeded"), "resolve"},
		{errors.New("failed to connect to site: failed to find address of a.ton (ab) in DHT, err: x"), "dht"},
	}
	for _, c := range cases {
		client = &http.Client{Transport: failingRT{c.err}}
		rec := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodGet, "http://a.ton/", nil)
		req.Host = "a.ton"
		(&proxy{}).ServeHTTP(rec, req)
		if got := rec.Header().Get("X-Tonutils-Error"); got != c.want || rec.Code != http.StatusBadGateway {
			t.Errorf("%v: header %q code %d, want %q 502", c.err, got, rec.Code, c.want)
		}
	}
}

// A host name inside the error text must not decide the kind.
func TestErrorKindIgnoresTheHostName(t *testing.T) {
	err := &url.Error{Op: "Get", URL: "http://xstorage.ton/", Err: errors.New("dial tcp: connection refused")}
	if k := errorKind(err); k != "other" {
		t.Fatalf("got %q; the name xstorage.ton made it look like a storage failure", k)
	}
}
