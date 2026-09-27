package main

import (
	"context"
	"expvar"
	"flag"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
	"github.com/xssnick/tonutils-go/liteclient"
	"github.com/xssnick/tonutils-proxy/cmd/proxy-cli/config"
	"github.com/xssnick/tonutils-proxy/proxy"
	"github.com/xssnick/tonutils-proxy/proxy/transport"
	"net/http"
	"net/http/pprof"
	"os"
	"os/signal"
	"time"
)

var GitCommit = "dev"

func main() {
	var addr = flag.String("addr", "127.0.0.1:8080", "The addr of the proxy.")
	var verbosity = flag.Int("verbosity", 2, "Debug logs")
	var blockHttp = flag.Bool("no-http", false, "Block ordinary http requests")
	var networkConfigPath = flag.String("global-config", "", "path to ton network config file")
	// ton2web fork
	var debugAddr = flag.String("debug-addr", "", "serve /debug/vars and /debug/pprof on this addr (keep it on localhost)")
	var headerTimeout = flag.Duration("rldp-header-timeout", transport.RLDPHeaderTimeout, "drop an RLDP connection that sends no response header within this, and retry once")
	var storageUpload = flag.Bool("storage-upload", transport.StorageUpload, "seed TON Storage bags that were visited")
	var siteIdle = flag.Duration("site-idle", transport.SiteIdleEvict, "forget an RLDP site unused for this long")
	var bagIdle = flag.Duration("bag-idle", transport.BagIdleStop, "stop a storage bag unused for this long")

	flag.Parse()

	transport.RLDPHeaderTimeout = *headerTimeout
	transport.StorageUpload = *storageUpload
	transport.SiteIdleEvict = *siteIdle
	transport.BagIdleStop = *bagIdle

	log.Logger = log.Output(zerolog.ConsoleWriter{Out: os.Stdout}).Level(zerolog.InfoLevel)
	if *verbosity >= 3 {
		log.Logger = log.Logger.Level(zerolog.DebugLevel)
	}

	log.Info().Msg("Version:" + GitCommit)

	if *debugAddr != "" {
		mux := http.NewServeMux()
		mux.Handle("/debug/vars", expvar.Handler())
		mux.HandleFunc("/debug/pprof/", pprof.Index)
		mux.HandleFunc("/debug/pprof/cmdline", pprof.Cmdline)
		mux.HandleFunc("/debug/pprof/profile", pprof.Profile)
		mux.HandleFunc("/debug/pprof/symbol", pprof.Symbol)
		mux.HandleFunc("/debug/pprof/trace", pprof.Trace)
		go func() {
			srv := &http.Server{Addr: *debugAddr, Handler: mux, ReadHeaderTimeout: 5 * time.Second}
			log.Info().Str("addr", *debugAddr).Msg("debug endpoint")
			if err := srv.ListenAndServe(); err != nil {
				log.Error().Err(err).Msg("debug endpoint failed")
			}
		}()
	}
	if *blockHttp {
		log.Info().Msg("Ordinary HTTP Will be blocked (flag --no-http set)")
	}

	cfg, err := config.LoadConfig("./")
	if err != nil {
		log.Fatal().Err(err).Msg("failed to load config")
		return
	}

	var customTinNetCfg *liteclient.GlobalConfig
	if cfg.CustomTunnelNetworkConfigPath != "" {
		customTinNetCfg, err = liteclient.GetConfigFromFile(cfg.CustomTunnelNetworkConfigPath)
		if err != nil {
			log.Fatal().Err(err).Msg("failed to load custom net config for tun")
		}
	}

	tunnelEnabled := cfg.TunnelConfig != nil && cfg.TunnelConfig.NodesPoolConfigPath != ""
	closerCtx, stop := context.WithCancel(context.Background())

	var tunnelCtx context.Context
	if tunnelEnabled {
		var cancel context.CancelFunc
		tunnelCtx, cancel = context.WithCancel(context.Background())
		proxy.OnTunnelStopped = cancel
	}

	go func() {
		err = proxy.RunProxy(closerCtx, *addr, cfg.ADNLKey, nil, "CLI "+GitCommit, *blockHttp, *networkConfigPath, cfg.TunnelConfig, customTinNetCfg)
		if err != nil {
			log.Fatal().Err(err).Msg("proxy failed")
			return
		}
	}()

	c := make(chan os.Signal, 1)
	signal.Notify(c, os.Interrupt)
	<-c
	stop()

	log.Info().Msg("Received interrupt signal, shutting down...")
	if tunnelEnabled {
		log.Info().Msg("Committing tunnel payments...")
		<-tunnelCtx.Done()
	}
	log.Info().Msg("Shutdown complete")
}
