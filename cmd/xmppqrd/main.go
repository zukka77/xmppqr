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
	"os/exec"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

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
	"github.com/danielinux/xmppqr/internal/sm"
	"github.com/danielinux/xmppqr/internal/spqr"
	"github.com/danielinux/xmppqr/internal/storage"
	"github.com/danielinux/xmppqr/internal/storage/memstore"
	"github.com/danielinux/xmppqr/internal/storage/pg"
	xtls "github.com/danielinux/xmppqr/internal/tls"
	"github.com/danielinux/xmppqr/internal/vcard"
	"github.com/danielinux/xmppqr/internal/wolfcrypt"
)

func main() {
	cfgPath := flag.String("config", "", "path to YAML config (optional; uses defaults if absent)")
	devUser := flag.String("dev-user", "test", "dev: pre-create this user with the given password")
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

	logger, err := xlog.New(cfg.Log)
	if err != nil {
		fatal("log: %v", err)
	}
	slog.SetDefault(logger)

	if err := ensureCert(cfg); err != nil {
		fatal("cert: %v", err)
	}

	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()

	stores, pgDB, err := openStores(ctx, cfg)
	if err != nil {
		fatal("store: %v", err)
	}
	if pgDB != nil {
		defer pgDB.Close()
	}

	if err := seedDevUser(context.Background(), stores, *devUser, cfg.Server.Domain, *devPass); err != nil {
		fatal("seed user: %v", err)
	}
	logger.Info("seeded dev user", "jid", *devUser+"@"+cfg.Server.Domain)

	rt := router.New()
	resumeStore := sm.NewStore(100_000)

	mods, uploadBackend := buildModules(cfg, stores, rt, logger)

	tlsCtx, err := buildTLSContext(cfg)
	if err != nil {
		fatal("tls context: %v", err)
	}
	defer tlsCtx.Close()

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

	uploadSrv := &http.Server{Addr: cfg.Listeners.HTTPUpload, Handler: buildUploadMux(uploadBackend)}
	go func() {
		if err := uploadSrv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			logger.Error("upload server", "err", err)
		}
	}()
	logger.Info("upload listening", "addr", cfg.Listeners.HTTPUpload)

	sessionCfg := c2s.SessionConfig{
		Domain:         cfg.Server.Domain,
		Stores:         stores,
		Router:         rt,
		ResumeStore:    resumeStore,
		Logger:         logger,
		MaxStanzaBytes: 1 << 20,
		Modules:        mods,
	}

	go acceptLoop(ctx, ln, sessionCfg, logger)
	if startTLSLn != nil {
		go acceptSTARTTLSLoop(ctx, startTLSLn, sessionCfg, tlsCtx, logger)
	}

	<-ctx.Done()
	logger.Info("shutting down")
	ln.Close()
	if startTLSLn != nil {
		startTLSLn.Close()
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
	ps := pubsub.New(stores.PEP, rt, logger, int64(cfg.Modules.SPQRItemMaxBytes))
	ps.WithContactNotify(rosterMgr, capsCache)

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

	mods := &c2s.Modules{
		Disco:      disco.DefaultServer(),
		Roster:     rosterMgr,
		Presence:   presence.New(rt, rosterMgr, logger),
		VCard:      vcard.New(stores.PEP),
		Bookmarks:  bookmarks.New(stores.PEP),
		Block:      block.New(stores.Block),
		MAM:        mam.New(stores.MAM, logger),
		Carbons:    carbons.New(rt, logger),
		Push:       push.New(stores.Push, rt, cfg.Server.Domain, logger),
		HTTPUpload: uploadSvcFull,
		PubSub:     ps,
		PEP:        pep.New(ps, logger),
		MUC:        muc.New(cfg.Server.Domain, "conference", stores.MUC, rt, logger),
		Metrics:    metrics.New(nil),
		SPQRPolicy: spqr.DomainPolicy{SPQROnlyMode: false},
		Caps:       capsCache,
		IBR:        ibr.New(stores, cfg.Server.Domain, cfg.Modules.IBR),
	}
	return mods, diskBackend
}

func buildMetricsMux() http.Handler {
	mux := http.NewServeMux()
	mux.Handle("/metrics", metrics.Handler())
	mux.Handle("/debug/pprof/", http.DefaultServeMux)
	return mux
}

func buildUploadMux(backend *httpupload.DiskBackend) http.Handler {
	mux := http.NewServeMux()
	mux.Handle("/upload/", backend.PutHandler())
	mux.Handle("/download/", backend.GetHandler())
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

func ensureCert(cfg *config.Config) error {
	if cfg.TLS.CertFile != "" && cfg.TLS.KeyFile != "" {
		if _, err := os.Stat(cfg.TLS.CertFile); err == nil {
			if _, err := os.Stat(cfg.TLS.KeyFile); err == nil {
				return nil
			}
		}
	}
	dir := filepath.Join(os.TempDir(), "xmppqrd-dev-cert")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	cfg.TLS.CertFile = filepath.Join(dir, "cert.pem")
	cfg.TLS.KeyFile = filepath.Join(dir, "key.pem")
	if _, err := os.Stat(cfg.TLS.CertFile); err == nil {
		if _, err := os.Stat(cfg.TLS.KeyFile); err == nil {
			return nil
		}
	}
	cmd := exec.Command("openssl", "req",
		"-x509", "-newkey", "rsa:2048", "-nodes",
		"-days", "30",
		"-subj", "/CN="+cfg.Server.Domain,
		"-keyout", cfg.TLS.KeyFile,
		"-out", cfg.TLS.CertFile,
	)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("openssl: %w: %s", err, out)
	}
	return nil
}

func seedDevUser(ctx context.Context, stores *storage.Stores, username, domain, password string) error {
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
		Username:     username,
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
