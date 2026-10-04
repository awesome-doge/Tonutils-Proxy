package proxy

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
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

// A body that stops before its end, then a read error — what the RLDP transport hands over when
// a payload part never arrives or the site's server goes away mid-response.
type cutBody struct {
	data []byte
	done bool
}

func (c *cutBody) Read(p []byte) (int, error) {
	if c.done {
		return 0, io.ErrUnexpectedEOF
	}
	c.done = true
	return copy(p, c.data), nil
}
func (c *cutBody) Close() error { return nil }

type bodyRT struct {
	body   io.ReadCloser
	length int64
}

func (b bodyRT) RoundTrip(*http.Request) (*http.Response, error) {
	h := http.Header{"Content-Type": {"application/javascript"}}
	if b.length >= 0 {
		h.Set("Content-Length", strconv.FormatInt(b.length, 10))
	}
	return &http.Response{StatusCode: 200, Status: "200 OK", Header: h, Body: b.body, ContentLength: b.length}, nil
}

// through returns what an HTTP client reads from the proxy for one request to a .ton host.
func through(t *testing.T, rt http.RoundTripper) (n int, readErr error) {
	t.Helper()
	client = &http.Client{Transport: rt}
	srv := httptest.NewServer(&proxy{})
	defer srv.Close()
	req, _ := http.NewRequest(http.MethodGet, srv.URL+"/app.js", nil)
	req.Host = "a.ton"
	res, err := http.DefaultTransport.RoundTrip(req)
	if err != nil {
		t.Fatalf("request: %v", err)
	}
	defer res.Body.Close()
	if res.StatusCode != 200 {
		t.Fatalf("status %d", res.StatusCode)
	}
	body, readErr := io.ReadAll(res.Body)
	return len(body), readErr
}

// ton2web: a cut body must not arrive looking whole. Without a Content-Length nothing downstream
// can tell a clean end from a cut, so the proxy has to break the connection itself.
func TestACutBodyIsNotPassedOffAsWhole(t *testing.T) {
	part := bytes.Repeat([]byte("a"), 50000)

	n, err := through(t, bodyRT{body: &cutBody{data: part}, length: -1})
	if err == nil {
		t.Fatalf("no Content-Length, cut after %d bytes: the client read %d bytes and no error — a cut file that looks complete", len(part), n)
	}

	n, err = through(t, bodyRT{body: &cutBody{data: part}, length: 200000})
	if err == nil {
		t.Fatalf("Content-Length 200000, cut after %d bytes: the client read %d bytes and no error", len(part), n)
	}

	// and a whole body is still a whole body, with and without a length
	for _, length := range []int64{-1, 50000} {
		n, err = through(t, bodyRT{body: io.NopCloser(bytes.NewReader(part)), length: length})
		if err != nil || n != len(part) {
			t.Fatalf("whole body (length %d): read %d bytes, err %v", length, n, err)
		}
	}
}
