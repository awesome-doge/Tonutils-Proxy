package transport

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"github.com/rs/zerolog/log"
	"github.com/xssnick/tonutils-go/adnl"
	"github.com/xssnick/tonutils-go/adnl/address"
	"github.com/xssnick/tonutils-go/adnl/rldp"
	"github.com/xssnick/tonutils-go/tl"
	"github.com/xssnick/tonutils-go/ton/dns"
	"github.com/xssnick/tonutils-storage/storage"
	"io"
	"net/http"
	"reflect"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

const _ChunkSize = 1 << 17
const _RLDPMaxAnswerSize = 2*_ChunkSize + 1024

type DHT interface {
	StoreAddress(ctx context.Context, addresses address.List, ttl time.Duration, ownerKey ed25519.PrivateKey) (int, []byte, error)
	FindAddresses(ctx context.Context, key []byte) (*address.List, ed25519.PublicKey, error)
	Close()
}

type Resolver interface {
	Resolve(ctx context.Context, domain string) (*dns.Domain, error)
}

type RLDP interface {
	Close()
	DoQuery(ctx context.Context, maxAnswerSize uint64, query, result tl.Serializable) error
	SetOnQuery(handler func(transferId []byte, query *rldp.Query) error)
	SetOnDisconnect(handler func())
	SendAnswer(ctx context.Context, maxAnswerSize uint64, timeoutAt uint32, queryId, transferId []byte, answer tl.Serializable) error
	GetADNL() rldp.ADNL
}

type ADNL interface {
	RemoteAddr() string
	GetID() []byte
	Query(ctx context.Context, req, result tl.Serializable) error
	SetCustomMessageHandler(handler func(msg *adnl.MessageCustom) error)
	SetDisconnectHandler(handler func(addr string, key ed25519.PublicKey))
	GetDisconnectHandler() func(addr string, key ed25519.PublicKey)
	SendCustomMessage(ctx context.Context, req tl.Serializable) error
	GetCloserCtx() context.Context
	Close()
}

type bagInfo struct {
	torrent    *storage.Torrent
	downloader storage.TorrentDownloader
	cancel     context.CancelFunc // ends the downloader's search context (ton2web fork)
}

var newRLDP = func(a ADNL) RLDP {
	return rldp.NewClientV2(a)
}

// siteInfo is one host's connection state. mx guards the fields and is never held across
// network I/O (ton2web fork; see sites.go).
type siteInfo struct {
	Actor any

	LastUsed    int64
	LastSuccess int64
	connecting  *flight
	mx          sync.Mutex
}

type rldpInfo struct {
	ActiveClient RLDP
	server       *serverClient // the shared client ActiveClient belongs to

	ID     ed25519.PublicKey
	NodeID []byte // the site's ADNL id (DHT key)
	Addr   string
}

type Transport struct {
	dht              DHT
	resolver         Resolver
	storageConnector storage.NetConnector
	store            *VirtualStorage
	gate             *adnl.Gateway

	activeSites map[string]*siteInfo
	dns         *dnsCache
	dhtCache    map[string]*dhtRecord
	servers     map[string]*serverClient // one RLDP client per server key (see sites.go)
	dialRLDP    func(key ed25519.PublicKey, addr, host string) (RLDP, error)

	activeRequests map[string]*payloadStream
	globalCtx      context.Context
	stop           func()
	mx             sync.RWMutex
}

func NewTransport(gate *adnl.Gateway, dht DHT, resolver Resolver, storeConn storage.NetConnector, store *VirtualStorage) *Transport {
	t := &Transport{
		gate:             gate,
		dht:              dht,
		resolver:         resolver,
		storageConnector: storeConn,
		store:            store,
		activeRequests:   map[string]*payloadStream{},
		activeSites:      map[string]*siteInfo{},
		dns:              newDNSCache(),
		dhtCache:         map[string]*dhtRecord{},
		servers:          map[string]*serverClient{},
	}
	t.dialRLDP = t.connectRLDP
	t.globalCtx, t.stop = context.WithCancel(context.Background())
	go t.cleaner()
	return t
}

func (t *Transport) Stop() {
	t.stop()
}

func (t *Transport) cleaner() {
	for {
		select {
		case <-t.globalCtx.Done():
			return
		case <-time.After(3 * time.Second):
		}

		sites := make(map[string]*siteInfo, len(t.activeSites))
		t.mx.RLock()
		for s, info := range t.activeSites {
			sites[s] = info
		}
		t.mx.RUnlock()

		now := time.Now().Unix()
		for s, info := range sites {
			if info.mx.TryLock() {
				idle := now - atomic.LoadInt64(&info.LastUsed)
				switch act := info.Actor.(type) {
				case *bagInfo:
					// stop bags that were not used for BagIdleStop
					if idle > int64(BagIdleStop.Seconds()) {
						t.forgetSite(s, info)
						t.stopBag(act)
						log.Debug().Hex("bag_id", act.torrent.BagID).Msg("stopped unused bag")
					}
				case *rldpInfo:
					// upstream never evicted RLDP sites: the map only grew. The server's client
					// may serve other sites, so it is closed separately, when the SERVER is idle.
					if idle > int64(SiteIdleEvict.Seconds()) && info.connecting == nil {
						t.forgetSite(s, info)
						_ = act
					}
				}
				info.mx.Unlock()
			}
		}
		t.closeIdleServers(now)
	}
}

func (t *Transport) forgetSite(host string, info *siteInfo) {
	t.mx.Lock()
	if t.activeSites[host] == info {
		delete(t.activeSites, host)
	}
	t.mx.Unlock()
}

func (t *Transport) connectRLDP(key ed25519.PublicKey, addr, host string) (RLDP, error) {
	a, err := t.gate.RegisterClient(addr, key)
	if err != nil {
		return nil, fmt.Errorf("failed to init adnl for rldp connection %s, err: %w", addr, err)
	}

	r := newRLDP(a)
	r.SetOnQuery(t.getRLDPQueryHandler(r))
	r.SetOnDisconnect(t.removeServer(hex.EncodeToString(key), r))

	return r, nil
}

// removeServer runs when a server's client disconnects: forget it, and every site that used it.
func (t *Transport) removeServer(key string, rl RLDP) func() {
	return func() {
		t.mx.Lock()
		if sc := t.servers[key]; sc != nil && sc.rl == rl {
			delete(t.servers, key)
		}
		t.mx.Unlock()
		t.clearClient(rl)
	}
}

// clearClient detaches a (dead) client from every site that uses it, so they reconnect.
func (t *Transport) clearClient(rl RLDP) {
	t.mx.RLock()
	sites := make([]*siteInfo, 0, len(t.activeSites))
	for _, s := range t.activeSites {
		sites = append(sites, s)
	}
	t.mx.RUnlock()
	for _, s := range sites {
		s.mx.Lock()
		if act, ok := s.Actor.(*rldpInfo); ok && act.ActiveClient == rl {
			act.ActiveClient = nil
		}
		s.mx.Unlock()
	}
}

func (t *Transport) getRLDPQueryHandler(r RLDP) func(transferId []byte, query *rldp.Query) error {
	return func(transferId []byte, query *rldp.Query) error {
		switch req := query.Data.(type) {
		case GetNextPayloadPart:
			t.mx.RLock()
			stream := t.activeRequests[hex.EncodeToString(req.ID)]
			t.mx.RUnlock()

			if stream == nil {
				return fmt.Errorf("unknown request id %s", hex.EncodeToString(req.ID))
			}

			part, err := handleGetPart(req, stream)
			if err != nil {
				return fmt.Errorf("handle part err: %w", err)
			}

			ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
			err = r.SendAnswer(ctx, query.MaxAnswerSize, query.Timeout, query.ID, transferId, part)
			cancel()
			if err != nil {
				return fmt.Errorf("failed to send answer: %w", err)
			}

			if part.IsLast {
				t.mx.Lock()
				delete(t.activeRequests, hex.EncodeToString(req.ID))
				t.mx.Unlock()
				_ = stream.Data.Close()
			}

			return nil
		}
		return fmt.Errorf("unexpected query type %s", reflect.TypeOf(query.Data))
	}
}

func handleGetPart(req GetNextPayloadPart, stream *payloadStream) (*PayloadPart, error) {
	stream.mx.Lock()
	defer stream.mx.Unlock()

	offset := int(req.Seqno * req.MaxChunkSize)
	if offset != stream.nextOffset {
		return nil, fmt.Errorf("failed to get part for stream %s, incorrect offset %d, should be %d", hex.EncodeToString(req.ID), offset, stream.nextOffset)
	}

	var last bool
	data := make([]byte, req.MaxChunkSize)
	n, err := stream.Data.Read(data)
	if err != nil {
		if err != io.EOF {
			return nil, fmt.Errorf("failed to read chunk %d, err: %w", req.Seqno, err)
		}
		last = true
	}
	stream.nextOffset += n

	return &PayloadPart{
		Data:    data[:n],
		Trailer: nil, // TODO: trailer
		IsLast:  last,
	}, nil
}

func (t *Transport) RoundTrip(request *http.Request) (_ *http.Response, err error) {
	host := request.Host
	if host == "" {
		host = request.URL.Host
	}
	metrics.requests.Add(1)

	// Only a request we can safely send twice is retried after a stall.
	retryable := (request.Method == http.MethodGet || request.Method == http.MethodHead) &&
		(request.Body == nil || request.Body == http.NoBody)

	var stalled RLDP
	for attempt := 0; ; attempt++ {
		tm := time.Now()
		actor, err := t.actorFor(request.Context(), host, stalled)
		metrics.waitMs.Add(bucket(time.Since(tm)), 1)
		if err != nil {
			return nil, fmt.Errorf("failed to connect to site: %w", err)
		}
		log.Debug().Str("host", host).Dur("took", time.Since(tm)).Msg("site ready")

		switch act := actor.(type) {
		case *bagInfo:
			metrics.bagRequests.Add(1)
			s := t.site(host)
			resp, err := t.doTorrent(act, request, s)
			if err != nil {
				return nil, fmt.Errorf("failed to request file from storage: %w", err)
			}
			atomic.StoreInt64(&s.LastSuccess, time.Now().Unix())
			return resp, nil

		case *rldpInfo:
			client := act.ActiveClient
			if client == nil { // dropped between actorFor and here
				continue
			}
			resp, err := t.doRldpHttp(client, host, request)
			if err == nil {
				atomic.StoreInt64(&act.server.lastHeaderAt, time.Now().UnixNano())
				if attempt > 0 {
					metrics.rldpRetryOK.Add(1)
				}
				metrics.rldpOK.Add(1)
				atomic.StoreInt64(&t.site(host).LastSuccess, time.Now().Unix())
				return resp, nil
			}
			if errors.Is(err, ErrStall) {
				metrics.rldpStall.Add(1)
				if time.Since(time.Unix(0, atomic.LoadInt64(&act.server.lastHeaderAt))) < recentHeaderGrace {
					// the connection answered another request just now: slow page, live peer
					metrics.rldpFail.Add(1)
					return nil, fmt.Errorf("failed to request rldp-http site: %w", err)
				}
				// The connection is not answering: forget it and its DHT address, then try
				// once more from a fresh lookup (maybe the site moved, maybe the peer died).
				t.dropClient(host, act, client)
				if retryable && attempt == 0 && request.Context().Err() == nil {
					stalled = client
					continue
				}
			}
			metrics.rldpFail.Add(1)
			return nil, fmt.Errorf("failed to request rldp-http site: %w", err)

		default:
			return nil, fmt.Errorf("failed to connect to site: unknown actor %T", actor)
		}
	}
}

func (t *Transport) doTorrent(bag *bagInfo, request *http.Request, si *siteInfo) (*http.Response, error) {
	fileName := request.URL.Path
	if strings.HasPrefix(fileName, "/") {
		fileName = fileName[1:]
	}

	if fileName == "" {
		fileName = "index.html"
	}

	if request.Body != nil {
		tmp := make([]byte, 4096)
		for { // discard body
			_, err := request.Body.Read(tmp)
			if err != nil {
				if err == io.EOF {
					break
				}
				return nil, fmt.Errorf("failed to read request body: %w", err)
			}
		}
	}

	fileInfo, err := bag.torrent.GetFileOffsets(fileName)
	if err != nil {
		return &http.Response{
			Status:        "Not Found",
			StatusCode:    404,
			Proto:         "HTTP/1.1",
			ProtoMajor:    1,
			ProtoMinor:    1,
			Header:        map[string][]string{},
			ContentLength: 0,
			Trailer:       map[string][]string{},
			Request:       request,
		}, nil
	}

	pieces := make([]byte, bag.torrent.Info.PiecesNum())

	var typ string
	if strings.Contains(fileName, ".") {
		ext := strings.Split(fileName, ".")
		typ = typeByExtension(ext[len(ext)-1])
	}
	if typ == "" {
		typ = "application/octet-stream"
	}

	fileLastIndex := fileInfo.Size
	if fileLastIndex > 0 {
		fileLastIndex -= 1
	}
	hasRange, from, to, err := t.parseRange(request, fileLastIndex)
	if err != nil {
		log.Error().Err(err).Msg("invalid range")

		return &http.Response{
			Status:        "Invalid range",
			StatusCode:    416,
			Proto:         "HTTP/1.1",
			ProtoMajor:    1,
			ProtoMinor:    1,
			Header:        map[string][]string{},
			ContentLength: 0,
			Trailer:       map[string][]string{},
			Request:       request,
		}, nil
	}

	piecesMap := make(map[uint32]bool, fileInfo.ToPiece-fileInfo.FromPiece+1)

	var offFrom, offTo uint64 = 0, 0
	for piece := fileInfo.FromPiece; piece <= fileInfo.ToPiece; piece++ {
		sz := bag.torrent.Info.PieceSize
		if piece == fileInfo.ToPiece {
			sz = fileInfo.ToPieceOffset
		}
		if piece == fileInfo.FromPiece {
			sz -= fileInfo.FromPieceOffset
		}

		offTo += uint64(sz)
		if offTo >= from && offFrom <= to {
			pieces[piece] = 1
			piecesMap[piece] = true
		}
		offFrom = offTo
	}

	httpResp := &http.Response{
		Status:        "OK",
		StatusCode:    http.StatusOK,
		Proto:         "HTTP/1.1",
		ProtoMajor:    1,
		ProtoMinor:    1,
		Header:        map[string][]string{},
		ContentLength: int64((to + 1) - from),
		Trailer:       map[string][]string{},
		Request:       request,
	}

	if hasRange {
		httpResp.StatusCode = http.StatusPartialContent
		httpResp.Status = http.StatusText(http.StatusPartialContent)

		httpResp.Header.Set("Content-Range", fmt.Sprintf("bytes %d-%d/%d", from, to, fileInfo.Size))
		httpResp.Header.Set("Content-Length", fmt.Sprint((to+1)-from))
	} else {
		httpResp.Header.Set("Content-Length", fmt.Sprint(fileInfo.Size))
		httpResp.Header.Set("Accept-Ranges", "bytes")
	}
	httpResp.Header.Set("Content-Type", typ)

	if len(pieces) > 0 {
		fetch := storage.NewPreFetcher(request.Context(), bag.torrent, func(event storage.Event) {}, 64, pieces)
		stream := newDataStreamer()
		httpResp.Body = stream

		go func() {
			defer fetch.Stop()

			err := t.proxyOrdered(request.Context(), fileInfo, piecesMap, fetch, stream, si, bag.torrent.Info.PieceSize, from, to)
			if err != nil {
				_ = stream.Close()
				if !errors.Is(err, context.Canceled) {
					log.Error().Err(err).Msg("download ordered err")
				}
				return
			}
			stream.Finish()
		}()
	}

	return httpResp, nil
}

func (t *Transport) doRldpHttp(client RLDP, host string, request *http.Request) (*http.Response, error) {
	qid := make([]byte, 32)
	_, err := rand.Read(qid)
	if err != nil {
		return nil, err
	}

	req := Request{
		ID:     qid,
		Method: request.Method,
		// ton2web: the path and query only. A request that came with a Host header and a bare path
		// (how a reverse proxy in front of this one asks) has no host in its URL, and URL.String()
		// then wrote "http:///path": a server that hands that to nginx as the request target gets
		// 400 Bad Request back. The whole address ("http://name.ton/path") is no better: one live
		// site answered 404 to it and 200 to the path. The host travels in the Host header.
		URL:     request.URL.RequestURI(),
		Version: "HTTP/1.1",
		Headers: []Header{
			{
				Name:  "Host",
				Value: host,
			},
		},
	}

	if request.ContentLength > 0 {
		req.Headers = append(req.Headers, Header{
			Name:  "Content-Length",
			Value: fmt.Sprint(request.ContentLength),
		})
	}

	for k, v := range request.Header {
		for _, hdr := range v {
			req.Headers = append(req.Headers, Header{
				Name:  k,
				Value: hdr,
			})
		}
	}

	if request.Body != nil {
		stream := newDataStreamer()

		// chunked stream reader
		go func() {
			defer request.Body.Close()

			// local err: upstream wrote the enclosing function's err from this goroutine (data race)
			var n int
			var err error
			for {
				buf := make([]byte, 4096)
				n, err = request.Body.Read(buf)
				if err != nil {
					if errors.Is(err, io.EOF) {
						_, err = stream.Write(buf[:n])
						if err == nil {
							stream.Finish()
							break
						}
					}
					_ = stream.Close()
					break
				}

				_, err = stream.Write(buf[:n])
				if err != nil {
					_ = stream.Close()
					break
				}
			}
		}()

		t.mx.Lock()
		t.activeRequests[hex.EncodeToString(qid)] = &payloadStream{
			Data:      stream,
			ValidTill: time.Now().Add(15 * time.Second),
		}
		t.mx.Unlock()

		defer func() {
			t.mx.Lock()
			delete(t.activeRequests, hex.EncodeToString(qid))
			t.mx.Unlock()
		}()
	}

	var res Response
	tm := time.Now()
	hctx, hcancel := context.WithTimeout(request.Context(), RLDPHeaderTimeout)
	err = client.DoQuery(hctx, _RLDPMaxAnswerSize, req, &res)
	hcancel()
	if err != nil {
		if request.Context().Err() == nil && errors.Is(hctx.Err(), context.DeadlineExceeded) {
			return nil, ErrStall
		}
		return nil, fmt.Errorf("failed to query http over rldp: %w", err)
	}
	metrics.headerMs.Add(bucket(time.Since(tm)), 1)

	httpResp := &http.Response{
		Status:        res.Reason,
		StatusCode:    int(res.StatusCode),
		Proto:         "HTTP/1.1",
		ProtoMajor:    1,
		ProtoMinor:    1,
		Header:        map[string][]string{},
		ContentLength: -1,
		Trailer:       map[string][]string{},
		Request:       request,
	}

	for _, header := range res.Headers {
		httpResp.Header.Add(header.Name, header.Value)
	}

	// upstream read this from the REQUEST's headers, giving POST responses the request body's length
	if ln := httpResp.Header.Get("Content-Length"); ln != "" {
		httpResp.ContentLength, err = strconv.ParseInt(ln, 10, 64)
		if err != nil {
			return nil, fmt.Errorf("failed to parse content length: %w", err)
		}
	}

	withPayload := !res.NoPayload && (httpResp.StatusCode < 300 || httpResp.StatusCode >= 400)

	dr := newDataStreamer()
	httpResp.Body = dr

	if withPayload {
		if httpResp.ContentLength > 0 && httpResp.ContentLength < (1<<22) {
			dr.buf = make([]byte, 0, httpResp.ContentLength)
		}

		go func() {
			seqno := int32(0)
			for withPayload {
				var part PayloadPart
				err := client.DoQuery(request.Context(), _RLDPMaxAnswerSize*1000, GetNextPayloadPart{
					ID:           qid,
					Seqno:        seqno,
					MaxChunkSize: _ChunkSize * 100,
				}, &part)
				if err != nil {
					_ = dr.Close()
					return
				}

				for _, tr := range part.Trailer {
					httpResp.Trailer[tr.Name] = []string{tr.Value}
				}

				withPayload = !part.IsLast
				_, err = dr.Write(part.Data)
				if err != nil {
					_ = dr.Close()
					return
				}

				if part.IsLast {
					dr.Finish()
				}

				seqno++
			}
		}()
	} else {
		dr.Finish()
	}

	return httpResp, nil
}

func (t *Transport) proxyOrdered(ctx context.Context, file *storage.FileInfo,
	piecesMap map[uint32]bool, fetch *storage.PreFetcher, stream *dataStreamer, si *siteInfo,
	pieceSz uint32, from, to uint64) error {
	var err error
	var currentPieceId uint32
	var currentPiece []byte

	notEmptyFile := file.FromPiece != file.ToPiece || file.FromPieceOffset != file.ToPieceOffset
	if notEmptyFile {
		var toOff uint64
		var wasFirst bool
		for piece := file.FromPiece; piece <= file.ToPiece; piece++ {
			sz := pieceSz
			if piece == file.ToPiece {
				sz = file.ToPieceOffset
			}
			if piece == file.FromPiece {
				sz -= file.FromPieceOffset
			}
			toOff += uint64(sz)

			if !piecesMap[piece] {
				continue
			}

			if piece != currentPieceId || currentPiece == nil {
				if currentPiece != nil {
					fetch.Free(currentPieceId)
				}

				atomic.StoreInt64(&si.LastUsed, time.Now().Unix())

				currentPiece, _, err = fetch.WaitGet(ctx, piece)
				if err != nil {
					return fmt.Errorf("failed to download piece %d: %w", piece, err)
				}

				currentPieceId = piece
			}
			part := currentPiece
			if piece == file.ToPiece {
				part = part[:file.ToPieceOffset]
			}
			if piece == file.FromPiece {
				part = part[file.FromPieceOffset:]
			}

			toOffIdx := toOff - 1
			if toOffIdx > to {
				diff := toOffIdx - to
				part = part[:len(part)-int(diff)]
			}

			fromOff := toOff - uint64(sz)
			if !wasFirst && from > fromOff {
				part = part[from-fromOff:]
			}
			wasFirst = true

			_, err = stream.Write(part)
			if err != nil {
				return fmt.Errorf("failed to write piece %d: %w", piece, err)
			}
		}
	}
	if err != nil {
		return err
	}

	if currentPiece != nil {
		fetch.Free(currentPieceId)
	}
	return nil
}

func (t *Transport) parseRange(request *http.Request, max uint64) (hasRange bool, from uint64, to uint64, err error) {
	rng := request.Header.Get("Range")
	if len(rng) > 6 && strings.HasPrefix(rng, "bytes=") {
		ranges := strings.SplitN(rng[6:], ",", 2)
		if len(ranges) > 1 {
			return false, 0, 0, fmt.Errorf("multiple ranges not supported")
		}

		rngArr := strings.SplitN(ranges[0], "-", 2)
		if len(rngArr) != 2 {
			return false, 0, 0, fmt.Errorf("invalid range format")
		}

		if rngArr[0] != "" {
			from, err = strconv.ParseUint(rngArr[0], 10, 64)
			if err != nil {
				return false, 0, 0, err
			}
			if from > max {
				return false, 0, 0, fmt.Errorf("invalid from range, over max")
			}
		}

		if rngArr[1] != "" {
			to, err = strconv.ParseUint(rngArr[1], 10, 64)
			if err != nil {
				return false, 0, 0, err
			}

			if to > max {
				return false, 0, 0, fmt.Errorf("invalid to range, over max")
			}
		} else {
			to = max
		}

		if from > to {
			return false, 0, 0, fmt.Errorf("invalid range, from > to (%d > %d)", from, to)
		}
		return true, from, to, nil
	}
	return false, 0, max, nil
}
