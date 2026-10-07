package transport

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/xssnick/tonutils-go/adnl/rldp"
	"github.com/xssnick/tonutils-go/tl"
)

// recordingRLDP answers 200 and keeps the request it was asked to send.
type recordingRLDP struct {
	sent Request
}

func (r *recordingRLDP) Close()                                     {}
func (r *recordingRLDP) SetOnQuery(func([]byte, *rldp.Query) error) {}
func (r *recordingRLDP) SetOnDisconnect(func())                     {}
func (r *recordingRLDP) GetADNL() rldp.ADNL                         { return nil }
func (r *recordingRLDP) SendAnswer(context.Context, uint64, uint32, []byte, []byte, tl.Serializable) error {
	return nil
}
func (r *recordingRLDP) DoQuery(_ context.Context, _ uint64, query, result tl.Serializable) error {
	if q, ok := query.(Request); ok {
		r.sent = q
	}
	if res, ok := result.(*Response); ok {
		*res = Response{Version: "HTTP/1.1", StatusCode: 200, Reason: "OK", NoPayload: true}
	}
	return nil
}

// ton2web, 2026-10-06. Asked the way a reverse proxy in front asks (a Host header and a bare
// path), the request went out with url "http:///" ("https:///" behind the gateway, which says
// X-Forwarded-Proto: https): URL.String() of a URL that has a scheme and no host. A server that
// hands the url to nginx as the request target answered 400 Bad Request to every name on it
// (105 names, none of which had ever opened through the gateway) and 200 to "/". The whole
// address is no fix: of 60 live sites one answered 404 to "http://name.ton/" and 200 to "/".
func TestTheRequestCarriesThePathAndTheHostTravelsInItsHeader(t *testing.T) {
	cases := []struct {
		name string
		make func() *http.Request
		want string
	}{
		{"a bare path with a Host header, scheme filled in by the proxy", func() *http.Request {
			r := httptest.NewRequest("GET", "/", nil)
			r.Host = "digitalmoney.ton"
			r.URL.Scheme = "https" // what proxy.go does with X-Forwarded-Proto
			return r
		}, "/"},
		{"a path and a query", func() *http.Request {
			r := httptest.NewRequest("GET", "/shop/item?x=1&y=a%20b", nil)
			r.Host = "digitalmoney.ton"
			r.URL.Scheme = "http"
			return r
		}, "/shop/item?x=1&y=a%20b"},
		{"the whole address, as a browser sends it to a forward proxy", func() *http.Request {
			r, _ := http.NewRequest("GET", "http://digitalmoney.ton/a/b?c=1", nil)
			return r
		}, "/a/b?c=1"},
		{"the whole address without a path", func() *http.Request {
			r, _ := http.NewRequest("GET", "http://digitalmoney.ton", nil)
			return r
		}, "/"},
	}
	for _, c := range cases {
		rec := &recordingRLDP{}
		tr := newTestTransport(nil, nil)
		req := c.make()
		req.Header.Set("User-Agent", "test")
		if _, err := tr.doRldpHttp(rec, "digitalmoney.ton", req); err != nil {
			t.Fatalf("%s: %v", c.name, err)
		}
		if rec.sent.URL != c.want {
			t.Errorf("%s: url %q, want %q", c.name, rec.sent.URL, c.want)
		}
		if len(rec.sent.Headers) == 0 || rec.sent.Headers[0].Name != "Host" || rec.sent.Headers[0].Value != "digitalmoney.ton" {
			t.Errorf("%s: the first header must be Host: digitalmoney.ton, got %+v", c.name, rec.sent.Headers)
		}
		if rec.sent.Method != "GET" || rec.sent.Version != "HTTP/1.1" {
			t.Errorf("%s: method %q version %q", c.name, rec.sent.Method, rec.sent.Version)
		}
	}
}
