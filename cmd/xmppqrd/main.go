package main

import (
	"context"
	"crypto/rand"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	_ "net/http/pprof"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/danielinux/xmppqr/internal/accountjid"
	"github.com/danielinux/xmppqr/internal/auth"
	"github.com/danielinux/xmppqr/internal/block"
	"github.com/danielinux/xmppqr/internal/bookmarks"
	"github.com/danielinux/xmppqr/internal/c2s"
	"github.com/danielinux/xmppqr/internal/caps"
	"github.com/danielinux/xmppqr/internal/carbons"
	"github.com/danielinux/xmppqr/internal/config"
	"github.com/danielinux/xmppqr/internal/disco"
	"github.com/danielinux/xmppqr/internal/httpupload"
	"github.com/danielinux/xmppqr/internal/ibr"
	xlog "github.com/danielinux/xmppqr/internal/log"
	"github.com/danielinux/xmppqr/internal/mam"
	"github.com/danielinux/xmppqr/internal/metrics"
	"github.com/danielinux/xmppqr/internal/muc"
	"github.com/danielinux/xmppqr/internal/pep"
	"github.com/danielinux/xmppqr/internal/presence"
	"github.com/danielinux/xmppqr/internal/pubsub"
	"github.com/danielinux/xmppqr/internal/push"
	"github.com/danielinux/xmppqr/internal/roster"
	"github.com/danielinux/xmppqr/internal/router"
	"github.com/danielinux/xmppqr/internal/s2s"
	"github.com/danielinux/xmppqr/internal/sm"
	"github.com/danielinux/xmppqr/internal/stanza"
	"github.com/danielinux/xmppqr/internal/x3dhpq"
	"github.com/danielinux/xmppqr/internal/storage"
	"github.com/danielinux/xmppqr/internal/storage/memstore"
	"github.com/danielinux/xmppqr/internal/storage/pg"
	xtls "github.com/danielinux/xmppqr/internal/tls"
	"github.com/danielinux/xmppqr/internal/vcard"
	"github.com/danielinux/xmppqr/internal/wolfcrypt"
)

func main() {
	cfgPath := flag.String("config", "", "path to YAML config (optional; uses defaults if absent)")
	devUser := flag.String("dev-user", "", "dev: pre-create this user with the given password")
	devPass := flag.String("dev-pass", "test", "dev: password for the pre-created user")
	flag.Parse()

	cfg, err := loadConfig(*cfgPath)
	if err != nil {
		fatal("config: %v", err)
	}
	if cfg.Server.Domain == "" {
		cfg.Server.Domain = "localhost"
	}
	if cfg.Listeners.C2SDirectTLS == "" {
		cfg.Listeners.C2SDirectTLS = ":5223"
	}
	if cfg.Listeners.C2SStartTLS == "" {
		cfg.Listeners.C2SStartTLS = ":5222"
	}
	if cfg.Listeners.AdminPProf == "" {
		cfg.Listeners.AdminPProf = "127.0.0.1:6060"
	}
	if cfg.Listeners.HTTPUpload == "" {
		cfg.Listeners.HTTPUpload = ":5443"
	}
	if err := requireServerCert(cfg); err != nil {
		fatal("config: %v", err)
	}

	logger, err := xlog.New(cfg.Log)
	if err != nil {
		fatal("log: %v", err)
	}
	slog.SetDefault(logger)

	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()

	stores, pgDB, err := openStores(ctx, cfg)
	if err != nil {
		fatal("store: %v", err)
	}
	if pgDB != nil {
		defer pgDB.Close()
	}

	if *devUser != "" {
		if err := seedDevUser(context.Background(), stores, *devUser, cfg.Server.Domain, *devPass); err != nil {
			fatal("seed user: %v", err)
		}
		logger.Info("seeded dev user", "jid", *devUser+"@"+cfg.Server.Domain)
	}

	rt := router.New()
	rt.SetLocalDomain(cfg.Server.Domain)
	resumeStore := sm.NewStore(100_000)
	rt.SetParkedStore(resumeStore)
	if stores.Offline != nil {
		rt.SetOfflineStore(stores.Offline)
	}

	mods, uploadBackend := buildModules(cfg, stores, rt, logger)

	tlsCtx, err := buildTLSContext(cfg)
	if err != nil {
		fatal("tls context: %v", err)
	}
	defer tlsCtx.Close()

	var s2sPool *s2s.Pool
	var s2sLn *s2s.Listener
	if cfg.S2S.Enabled {
		var s2sSecret [32]byte
		if _, err := wolfcrypt.Read(s2sSecret[:]); err != nil {
			if _, err2 := rand.Read(s2sSecret[:]); err2 != nil {
				fatal("s2s secret: %v", err2)
			}
		}
		s2sClientOpts := xtls.ClientOptions{
			MinVersion:         0x0303,
			PreferPQHybrid:     true,
			InsecureSkipVerify: cfg.S2S.InsecureSkipVerify,
		}
		s2sTLSCtx := tlsCtx
		if cfg.S2S.MTLSEnabled && cfg.S2S.CertFile != "" && cfg.S2S.KeyFile != "" {
			certPEM, err := os.ReadFile(cfg.S2S.CertFile)
			if err != nil {
				fatal("s2s mtls cert: %v", err)
			}
			keyPEM, err := os.ReadFile(cfg.S2S.KeyFile)
			if err != nil {
				fatal("s2s mtls key: %v", err)
			}
			s2sClientOpts.CertPEM = certPEM
			s2sClientOpts.KeyPEM = keyPEM
			var clientCAs []byte
			if cfg.S2S.ClientCAFile != "" {
				clientCAs, err = os.ReadFile(cfg.S2S.ClientCAFile)
				if err != nil {
					fatal("s2s mtls ca: %v", err)
				}
			}
			s2sTLSCtx, err = xtls.NewServerContext(certPEM, keyPEM, xtls.ServerOptions{
				MinVersion:     0x0303,
				PreferPQHybrid: cfg.TLS.PreferPQHybrid,
				ClientAuth:     true,
				ClientCAs:      clientCAs,
			})
			if err != nil {
				fatal("s2s server tls: %v", err)
			}
			defer s2sTLSCtx.Close()
		}
		s2sClientCtx, err := xtls.NewClientContext(nil, s2sClientOpts)
		if err != nil {
			fatal("s2s client tls: %v", err)
		}
		inboundAdapter := router.NewRouterInboundAdapter(rt, logger)
		s2sPool = s2s.New(cfg.Server.Domain, s2sSecret[:], s2sClientCtx, inboundAdapter, logger)
		if cfg.S2S.MTLSEnabled {
			s2sPool.SetMTLS(true)
		}
		rt.SetRemote(s2sPool)
		if cfg.Listeners.S2S != "" {
			s2sLn, err = s2s.NewListener(cfg.Listeners.S2S, s2sPool, s2sTLSCtx, logger)
			if err != nil {
				fatal("s2s listener: %v", err)
			}
			logger.Info("xmppqrd s2s listening", "addr", s2sLn.Addr())
		}
	}

	ln, err := xtls.Listen("tcp", cfg.Listeners.C2SDirectTLS, tlsCtx)
	if err != nil {
		fatal("listen direct-tls: %v", err)
	}
	logger.Info("xmppqrd direct-tls listening", "addr", cfg.Listeners.C2SDirectTLS, "domain", cfg.Server.Domain)

	var startTLSLn net.Listener
	if cfg.Listeners.C2SStartTLS != "" {
		startTLSLn, err = net.Listen("tcp", cfg.Listeners.C2SStartTLS)
		if err != nil {
			fatal("listen starttls: %v", err)
		}
		logger.Info("xmppqrd starttls listening", "addr", cfg.Listeners.C2SStartTLS)
	}

	metricsSrv := &http.Server{Addr: cfg.Listeners.AdminPProf, Handler: buildMetricsMux()}
	go func() {
		if err := metricsSrv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			logger.Error("metrics server", "err", err)
		}
	}()
	logger.Info("metrics listening", "addr", cfg.Listeners.AdminPProf)

	sessionCfg := c2s.SessionConfig{
		Domain:         cfg.Server.Domain,
		Stores:         stores,
		Router:         rt,
		ResumeStore:    resumeStore,
		Logger:         logger,
		MaxStanzaBytes: 1 << 20,
		Modules:        mods,
	}

	var wsHandler *c2s.WSHandler
	if cfg.Listeners.WebSocket != "" {
		wsHandler = c2s.NewWSHandler(sessionCfg)
		logger.Info("websocket handler registered on upload mux", "path", "/xmpp-websocket")
	}

	uploadSrv := &http.Server{Addr: cfg.Listeners.HTTPUpload, Handler: buildUploadMux(uploadBackend, wsHandler)}
	go func() {
		if err := uploadSrv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			logger.Error("upload server", "err", err)
		}
	}()
	logger.Info("upload listening", "addr", cfg.Listeners.HTTPUpload)

	go acceptLoop(ctx, ln, sessionCfg, logger)
	if startTLSLn != nil {
		go acceptSTARTTLSLoop(ctx, startTLSLn, sessionCfg, tlsCtx, logger)
	}
	if s2sLn != nil {
		go func() {
			if err := s2sLn.Accept(ctx); err != nil && !errors.Is(err, net.ErrClosed) {
				logger.Error("s2s accept", "err", err)
			}
		}()
	}

	<-ctx.Done()
	logger.Info("shutting down")
	ln.Close()
	if startTLSLn != nil {
		startTLSLn.Close()
	}
	if s2sLn != nil {
		s2sLn.Close()
	}
	if s2sPool != nil {
		s2sPool.Close()
	}
	shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer shutdownCancel()
	metricsSrv.Shutdown(shutdownCtx)
	uploadSrv.Shutdown(shutdownCtx)
	time.Sleep(200 * time.Millisecond)
}

func openStores(ctx context.Context, cfg *config.Config) (*storage.Stores, *pg.DB, error) {
	if cfg.DB.Driver == "postgres" {
		db, err := pg.Open(ctx, cfg.DB.DSN, cfg.DB.MaxConns)
		if err != nil {
			return nil, nil, fmt.Errorf("postgres: %w", err)
		}
		if cfg.DB.MigrateOnStart {
			if err := db.Migrate(ctx); err != nil {
				db.Close()
				return nil, nil, fmt.Errorf("migrate: %w", err)
			}
		}
		if err := db.NormalizeUsernamesToBareJIDs(ctx, cfg.Server.Domain); err != nil {
			db.Close()
			return nil, nil, fmt.Errorf("normalize users: %w", err)
		}
		return db.Stores(), db, nil
	}
	return memstore.New(), nil, nil
}

func buildModules(cfg *config.Config, stores *storage.Stores, rt *router.Router, logger *slog.Logger) (*c2s.Modules, *httpupload.DiskBackend) {
	var secret [32]byte
	if _, err := wolfcrypt.Read(secret[:]); err != nil {
		if _, err2 := rand.Read(secret[:]); err2 != nil {
			fatal("random secret: %v", err2)
		}
	}

	rosterMgr := roster.New(stores.Roster, logger)
	capsCache := caps.New()
	ps := pubsub.New(stores.PEP, rt, logger, int64(cfg.Modules.X3DHPQItemMaxBytes))
	ps.WithContactNotify(rosterMgr, capsCache)
	bundleLimits := x3dhpq.DefaultLimits()
	if cfg.Modules.X3DHPQItemMaxBytes > 0 {
		bundleLimits.ItemMaxBytes = int64(cfg.Modules.X3DHPQItemMaxBytes)
	}
	bundleRate := x3dhpq.NewRateChecker(bundleLimits)
	ps.WithPublishLimiter(bundleRate)
	pairLimiter := x3dhpq.NewPairLimiter(x3dhpq.DefaultPairLimiterConfig())
	verify := x3dhpq.NewVerifyDevice(verifyRouterAdapter{rt: rt}, pairLimiter, logger)

	uploadSvc := httpupload.New(
		cfg.Server.Domain,
		"http://"+cfg.Listeners.HTTPUpload,
		nil,
		50<<20,
		secret[:],
		24*time.Hour,
		logger,
	)
	diskBackend := httpupload.NewDiskBackend("/tmp/xmppqrd-uploads/", uploadSvc)

	uploadSvcFull := httpupload.New(
		cfg.Server.Domain,
		"http://"+cfg.Listeners.HTTPUpload,
		diskBackend,
		50<<20,
		secret[:],
		24*time.Hour,
		logger,
	)

	mamSvc := mam.New(stores.MAM, logger)

	mods := &c2s.Modules{
		Disco:      disco.DefaultServer(),
		Roster:     rosterMgr,
		Presence:   presence.New(rt, rosterMgr, logger),
		VCard:      vcard.New(stores.PEP),
		Bookmarks:  bookmarks.New(stores.PEP),
		Block:      block.New(stores.Block),
		MAM:        mamSvc,
		Carbons:    carbons.New(rt, logger),
		Push:       push.New(stores.Push, rt, cfg.Server.Domain, logger),
		HTTPUpload: uploadSvcFull,
		PubSub:     ps,
		PEP:        pep.New(ps, logger),
		MUC:        muc.New(cfg.Server.Domain, "conference", stores.MUC, mamSvc, ps, rt, logger),
		Metrics:    metrics.New(nil),
		X3DHPQPolicy: x3dhpq.DomainPolicy{X3DHPQOnlyMode: false},
		X3DHPQVerify: verify,
		X3DHPQPairLimiter: pairLimiter,
		Caps:       capsCache,
		IBR:        ibr.New(stores, cfg.Server.Domain, cfg.Modules.IBR),
	}
	return mods, diskBackend
}

// verifyRouterAdapter bridges router.Router to x3dhpq.Router. Defined in main
// to keep internal/x3dhpq free of a router import.
type verifyRouterAdapter struct {
	rt *router.Router
}

func (a verifyRouterAdapter) SessionsFor(bareJID string) []x3dhpq.RouterSession {
	sess := a.rt.SessionsFor(bareJID)
	out := make([]x3dhpq.RouterSession, len(sess))
	for i, s := range sess {
		out[i] = s
	}
	return out
}

func (a verifyRouterAdapter) RouteToFull(ctx context.Context, full stanza.JID, raw []byte) error {
	return a.rt.RouteToFull(ctx, full, raw)
}

func buildMetricsMux() http.Handler {
	mux := http.NewServeMux()
	mux.Handle("/metrics", metrics.Handler())
	mux.Handle("/debug/pprof/", http.DefaultServeMux)
	return mux
}

func buildUploadMux(backend *httpupload.DiskBackend, wsHandler http.Handler) http.Handler {
	mux := http.NewServeMux()
	mux.Handle("/upload/", backend.PutHandler())
	mux.Handle("/download/", backend.GetHandler())
	if wsHandler != nil {
		mux.Handle("/xmpp-websocket", wsHandler)
	}
	return mux
}

func loadConfig(path string) (*config.Config, error) {
	if path == "" {
		return config.Defaults(), nil
	}
	return config.Load(path)
}

func acceptLoop(ctx context.Context, ln *xtls.Listener, scfg c2s.SessionConfig, logger *slog.Logger) {
	for {
		conn, err := ln.Accept()
		if err != nil {
			if ctx.Err() != nil {
				return
			}
			logger.Warn("accept", "err", err)
			continue
		}
		tc, ok := conn.(*xtls.Conn)
		if !ok {
			conn.Close()
			continue
		}
		go func() {
			defer tc.Close()
			s := c2s.NewSession(tc, scfg)
			if err := s.Run(ctx); err != nil && !errors.Is(err, io.EOF) {
				logger.Info("session ended", "err", err)
			}
		}()
	}
}

func acceptSTARTTLSLoop(ctx context.Context, ln net.Listener, scfg c2s.SessionConfig, tlsCtx *xtls.Context, logger *slog.Logger) {
	for {
		conn, err := ln.Accept()
		if err != nil {
			if ctx.Err() != nil {
				return
			}
			logger.Warn("starttls accept", "err", err)
			continue
		}
		tcp, ok := conn.(*net.TCPConn)
		if !ok {
			conn.Close()
			continue
		}
		go func() {
			if err := c2s.RunSTARTTLS(ctx, tcp, tlsCtx, scfg); err != nil && !errors.Is(err, io.EOF) {
				logger.Info("starttls session ended", "err", err)
			}
		}()
	}
}

func buildTLSContext(cfg *config.Config) (*xtls.Context, error) {
	cert, err := os.ReadFile(cfg.TLS.CertFile)
	if err != nil {
		return nil, fmt.Errorf("read cert: %w", err)
	}
	key, err := os.ReadFile(cfg.TLS.KeyFile)
	if err != nil {
		return nil, fmt.Errorf("read key: %w", err)
	}
	return xtls.NewServerContext(cert, key, xtls.ServerOptions{
		MinVersion:     0x0303,
		PreferPQHybrid: cfg.TLS.PreferPQHybrid,
	})
}

func requireServerCert(cfg *config.Config) error {
	if cfg.TLS.CertFile == "" {
		return errors.New("tls.cert_file is required")
	}
	if cfg.TLS.KeyFile == "" {
		return errors.New("tls.key_file is required")
	}
	if _, err := os.Stat(cfg.TLS.CertFile); err != nil {
		return fmt.Errorf("tls.cert_file: %w", err)
	}
	if _, err := os.Stat(cfg.TLS.KeyFile); err != nil {
		return fmt.Errorf("tls.key_file: %w", err)
	}
	return nil
}

func seedDevUser(ctx context.Context, stores *storage.Stores, username, domain, password string) error {
	accountJID, _, err := accountjid.Normalize(username, domain)
	if err != nil {
		return err
	}
	salt := make([]byte, 16)
	if _, err := rand.Read(salt); err != nil {
		return err
	}
	const iter = 4096
	c256, err := auth.DeriveSCRAMCreds([]byte(password), salt, iter, auth.SCRAMSHA256)
	if err != nil {
		return err
	}
	c512, err := auth.DeriveSCRAMCreds([]byte(password), salt, iter, auth.SCRAMSHA512)
	if err != nil {
		return err
	}
	encoded, err := auth.HashPasswordForStorage([]byte(password))
	if err != nil {
		return err
	}
	u := &storage.User{
		Username:     accountJID,
		ScramSalt:    salt,
		ScramIter:    iter,
		Argon2Params: encoded,
		StoredKey256: c256.StoredKey,
		ServerKey256: c256.ServerKey,
		StoredKey512: c512.StoredKey,
		ServerKey512: c512.ServerKey,
		CreatedAt:    time.Now(),
	}
	return stores.Users.Put(ctx, u)
}

func fatal(format string, args ...any) {
	fmt.Fprintf(os.Stderr, "xmppqrd: "+format+"\n", args...)
	os.Exit(1)
}
