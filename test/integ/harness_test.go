package integ_test

import (
	"context"
	"crypto/rand"
	"errors"
	"io"
	"log/slog"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	"github.com/danielinux/xmppqr/internal/auth"
	"github.com/danielinux/xmppqr/internal/block"
	"github.com/danielinux/xmppqr/internal/bookmarks"
	"github.com/danielinux/xmppqr/internal/c2s"
	"github.com/danielinux/xmppqr/internal/carbons"
	"github.com/danielinux/xmppqr/internal/disco"
	"github.com/danielinux/xmppqr/internal/httpupload"
	"github.com/danielinux/xmppqr/internal/mam"
	"github.com/danielinux/xmppqr/internal/metrics"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/danielinux/xmppqr/internal/muc"
	"github.com/danielinux/xmppqr/internal/pep"
	"github.com/danielinux/xmppqr/internal/presence"
	"github.com/danielinux/xmppqr/internal/pubsub"
	"github.com/danielinux/xmppqr/internal/push"
	"github.com/danielinux/xmppqr/internal/roster"
	"github.com/danielinux/xmppqr/internal/router"
	"github.com/danielinux/xmppqr/internal/sm"
	"github.com/danielinux/xmppqr/internal/stanza"
	"github.com/danielinux/xmppqr/internal/spqr"
	"github.com/danielinux/xmppqr/internal/storage"
	"github.com/danielinux/xmppqr/internal/storage/memstore"
	xtls "github.com/danielinux/xmppqr/internal/tls"
	"github.com/danielinux/xmppqr/internal/vcard"
	"github.com/danielinux/xmppqr/internal/wolfcrypt"
)

type Harness struct {
	Domain     string
	tlsLn      *xtls.Listener
	startTLSLn net.Listener
	tlsCtx     *xtls.Context
	stores     *storage.Stores
	rt         *router.Router
	carbMgr    *carbons.Manager
	cancel     context.CancelFunc
}

func NewHarness(t *testing.T) *Harness {
	t.Helper()

	dir := t.TempDir()
	certFile := filepath.Join(dir, "cert.pem")
	keyFile := filepath.Join(dir, "key.pem")

	domain := "localhost"

	cmd := exec.Command("openssl", "req",
		"-x509", "-newkey", "rsa:2048", "-nodes",
		"-days", "1",
		"-subj", "/CN="+domain,
		"-keyout", keyFile,
		"-out", certFile,
	)
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("openssl: %v: %s", err, out)
	}

	certPEM, err := os.ReadFile(certFile)
	if err != nil {
		t.Fatalf("read cert: %v", err)
	}
	keyPEM, err := os.ReadFile(keyFile)
	if err != nil {
		t.Fatalf("read key: %v", err)
	}

	tlsCtx, err := xtls.NewServerContext(certPEM, keyPEM, xtls.ServerOptions{MinVersion: 0x0303})
	if err != nil {
		t.Fatalf("tls server context: %v", err)
	}

	tlsLn, err := xtls.Listen("tcp", "127.0.0.1:0", tlsCtx)
	if err != nil {
		tlsCtx.Close()
		t.Fatalf("listen tls: %v", err)
	}

	startTLSLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		tlsLn.Close()
		tlsCtx.Close()
		t.Fatalf("listen starttls: %v", err)
	}

	stores := memstore.New()
	rt := router.New()
	resumeStore := sm.NewStore(10_000)

	var secret [32]byte
	if _, err := wolfcrypt.Read(secret[:]); err != nil {
		if _, err2 := rand.Read(secret[:]); err2 != nil {
			t.Fatalf("random secret: %v", err2)
		}
	}

	rosterMgr := roster.New(stores.Roster, slog.Default())
	ps := pubsub.New(stores.PEP, rt, slog.Default(), 65536)

	uploadSvc := httpupload.New(domain, "http://127.0.0.1:0", nil, 50<<20, secret[:], 24*time.Hour, slog.Default())

	carbMgr := carbons.New(rt, slog.Default())
	mods := &c2s.Modules{
		Disco:      disco.DefaultServer(),
		Roster:     rosterMgr,
		Presence:   presence.New(rt, rosterMgr, slog.Default()),
		VCard:      vcard.New(stores.PEP),
		Bookmarks:  bookmarks.New(stores.PEP),
		Block:      block.New(stores.Block),
		MAM:        mam.New(stores.MAM, slog.Default()),
		Carbons:    carbMgr,
		Push:       push.New(stores.Push, rt, domain, slog.Default()),
		HTTPUpload: uploadSvc,
		PubSub:     ps,
		PEP:        pep.New(ps, slog.Default()),
		MUC:        muc.New(domain, "conference."+domain, stores.MUC, rt, slog.Default()),
		Metrics:    metrics.New(prometheus.NewRegistry()),
		SPQRPolicy: spqr.DomainPolicy{SPQROnlyMode: false},
	}

	sessionCfg := c2s.SessionConfig{
		Domain:         domain,
		Stores:         stores,
		Router:         rt,
		ResumeStore:    resumeStore,
		Logger:         slog.Default(),
		MaxStanzaBytes: 1 << 20,
		Modules:        mods,
	}

	ctx, cancel := context.WithCancel(context.Background())

	go func() {
		for {
			conn, err := tlsLn.Accept()
			if err != nil {
				if ctx.Err() != nil {
					return
				}
				continue
			}
			tc, ok := conn.(*xtls.Conn)
			if !ok {
				conn.Close()
				continue
			}
			go func() {
				defer tc.Close()
				s := c2s.NewSession(tc, sessionCfg)
				if err := s.Run(ctx); err != nil && !errors.Is(err, io.EOF) {
					_ = err
				}
			}()
		}
	}()

	go func() {
		for {
			conn, err := startTLSLn.Accept()
			if err != nil {
				if ctx.Err() != nil {
					return
				}
				continue
			}
			tcp, ok := conn.(*net.TCPConn)
			if !ok {
				conn.Close()
				continue
			}
			go func() {
				if err := c2s.RunSTARTTLS(ctx, tcp, tlsCtx, sessionCfg); err != nil && !errors.Is(err, io.EOF) {
					_ = err
				}
			}()
		}
	}()

	return &Harness{
		Domain:     domain,
		tlsLn:      tlsLn,
		startTLSLn: startTLSLn,
		tlsCtx:     tlsCtx,
		stores:     stores,
		rt:         rt,
		carbMgr:    carbMgr,
		cancel:     cancel,
	}
}

func (h *Harness) TLSAddr() string {
	return h.tlsLn.Addr().String()
}

func (h *Harness) STARTTLSAddr() string {
	return h.startTLSLn.Addr().String()
}

func (h *Harness) AddUser(t *testing.T, username, password string) {
	t.Helper()
	if err := seedUser(context.Background(), h.stores, username, h.Domain, password); err != nil {
		t.Fatalf("AddUser %s: %v", username, err)
	}
}

func (h *Harness) Close() {
	h.cancel()
	h.tlsLn.Close()
	h.startTLSLn.Close()
	h.tlsCtx.Close()
}

func (h *Harness) MAMStore() storage.MAMStore {
	return h.stores.MAM
}

func (h *Harness) CarbonsEnabled(fullJID string) bool {
	j, err := stanza.Parse(fullJID)
	if err != nil {
		return false
	}
	return h.carbMgr.IsEnabled(j)
}

func (h *Harness) SessionsFor(bareJID string) []router.Session {
	return h.rt.SessionsFor(bareJID)
}

func seedUser(ctx context.Context, stores *storage.Stores, username, domain, password string) error {
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
	_ = domain
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
