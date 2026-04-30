package integ_test

import (
	"context"
	"crypto/rand"
	"encoding/xml"
	"errors"
	"io"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/danielinux/xmppqr/internal/auth"
	"github.com/danielinux/xmppqr/internal/block"
	"github.com/danielinux/xmppqr/internal/bookmarks"
	"github.com/danielinux/xmppqr/internal/c2s"
	"github.com/danielinux/xmppqr/internal/caps"
	"github.com/danielinux/xmppqr/internal/carbons"
	"github.com/danielinux/xmppqr/internal/disco"
	"github.com/danielinux/xmppqr/internal/httpupload"
	"github.com/danielinux/xmppqr/internal/ibr"
	"github.com/danielinux/xmppqr/internal/mam"
	"github.com/danielinux/xmppqr/internal/metrics"
	"github.com/danielinux/xmppqr/internal/muc"
	"github.com/danielinux/xmppqr/internal/pep"
	"github.com/danielinux/xmppqr/internal/presence"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/danielinux/xmppqr/internal/pubsub"
	"github.com/danielinux/xmppqr/internal/push"
	"github.com/danielinux/xmppqr/internal/roster"
	"github.com/danielinux/xmppqr/internal/router"
	"github.com/danielinux/xmppqr/internal/s2s"
	"github.com/danielinux/xmppqr/internal/sm"
	"github.com/danielinux/xmppqr/internal/spqr"
	"github.com/danielinux/xmppqr/internal/stanza"
	"github.com/danielinux/xmppqr/internal/storage"
	"github.com/danielinux/xmppqr/internal/storage/memstore"
	xtls "github.com/danielinux/xmppqr/internal/tls"
	"github.com/danielinux/xmppqr/internal/vcard"
	"github.com/danielinux/xmppqr/internal/wolfcrypt"
)

type PushRecord struct {
	Reg         *storage.PushRegistration
	Payload     push.Payload
	DeviceToken string
}

type recordingProvider struct {
	mu    sync.Mutex
	sends []PushRecord
}

func (r *recordingProvider) Name() string { return "push" }

func (r *recordingProvider) Send(_ context.Context, reg *storage.PushRegistration, p push.Payload) (push.Receipt, error) {
	token := extractDeviceTokenFromForm(reg.FormXML)
	r.mu.Lock()
	r.sends = append(r.sends, PushRecord{Reg: reg, Payload: p, DeviceToken: token})
	r.mu.Unlock()
	return push.Receipt{ID: "ok", Status: 200}, nil
}

func extractDeviceTokenFromForm(formXML []byte) string {
	if len(formXML) == 0 {
		return ""
	}
	dec := xml.NewDecoder(
		func() io.Reader {
			return &bytesReader{b: formXML}
		}(),
	)
	inTarget := false
	for {
		tok, err := dec.Token()
		if err != nil {
			break
		}
		switch t := tok.(type) {
		case xml.StartElement:
			if t.Name.Local == "field" {
				inTarget = false
				for _, a := range t.Attr {
					if a.Name.Local == "var" && (a.Value == "device_token" || a.Value == "token") {
						inTarget = true
					}
				}
			}
			if t.Name.Local == "value" && inTarget {
				var v string
				if err2 := dec.DecodeElement(&v, &t); err2 == nil && v != "" {
					return v
				}
			}
		case xml.EndElement:
			if t.Name.Local == "field" {
				inTarget = false
			}
		}
	}
	return ""
}

type bytesReader struct {
	b   []byte
	pos int
}

func (r *bytesReader) Read(p []byte) (int, error) {
	if r.pos >= len(r.b) {
		return 0, io.EOF
	}
	n := copy(p, r.b[r.pos:])
	r.pos += n
	return n, nil
}

type Harness struct {
	Domain     string
	tlsLn      *xtls.Listener
	startTLSLn net.Listener
	tlsCtx     *xtls.Context
	stores     *storage.Stores
	rt         *router.Router
	carbMgr    *carbons.Manager
	cancel     context.CancelFunc
	uploadURL  string
	uploadSrv  *http.Server
	pushRec    *recordingProvider
	capsCache  *caps.Cache

	s2sPool *s2s.Pool
	s2sLn   *s2s.Listener
}

type HarnessOpts struct {
	Domain string
	EnableIBR bool
	EnableS2S bool
	// DialbackSecret is the shared HMAC secret for XEP-0220 dialback.
	// If nil and EnableS2S is true, a random secret is generated.
	// Federated peer harnesses must share the same secret to verify dialback.
	DialbackSecret []byte
}

func NewHarness(t *testing.T) *Harness {
	return newHarnessOpts(t, false)
}

func NewHarnessWithIBR(t *testing.T, allowIBR bool) *Harness {
	return newHarnessOpts(t, allowIBR)
}

// NewHarnessOpts builds a harness with full options.
//
// When opts.EnableS2S is true the harness:
//   - creates an s2s.Pool with a fresh dialback secret
//   - binds an S2S listener on 127.0.0.1:0 (use h.S2SAddr() to get the address)
//   - wires the pool as the router's RemoteRouter via router.SetRemote
//
// DNS SRV lookup is bypassed per-peer via h.AddS2SPeer(domain, addr).
// TLS is skipped for in-process tests (SetSkipTLS(true)); connections use plain TCP
// so no certificate is needed for the S2S channel.
func NewHarnessOpts(t *testing.T, opts HarnessOpts) *Harness {
	t.Helper()
	domain := opts.Domain
	if domain == "" {
		domain = "localhost"
	}
	h := newHarnessCore(t, domain, opts.EnableIBR)

	if opts.EnableS2S {
		secret := opts.DialbackSecret
		if len(secret) == 0 {
			var buf [32]byte
			if _, err := wolfcrypt.Read(buf[:]); err != nil {
				if _, err2 := rand.Read(buf[:]); err2 != nil {
					t.Fatalf("s2s secret: %v", err2)
				}
			}
			secret = buf[:]
		}

		inboundAdapter := router.NewRouterInboundAdapter(h.rt, slog.Default())
		pool := s2s.New(domain, secret, nil, inboundAdapter, slog.Default())
		pool.SetSkipTLS(true)

		s2sLn, err := s2s.NewListener("127.0.0.1:0", pool, nil, slog.Default())
		if err != nil {
			t.Fatalf("s2s listener: %v", err)
		}

		h.rt.SetLocalDomain(domain)
		h.rt.SetRemote(pool)

		h.s2sPool = pool
		h.s2sLn = s2sLn

		lnCtx, lnCancel := context.WithCancel(context.Background())
		t.Cleanup(lnCancel)
		go func() { _ = s2sLn.Accept(lnCtx) }()
	}

	return h
}

func newHarnessOpts(t *testing.T, allowIBR bool) *Harness {
	return newHarnessCore(t, "localhost", allowIBR)
}

func newHarnessCore(t *testing.T, domain string, allowIBR bool) *Harness {
	t.Helper()

	dir := t.TempDir()
	certFile := filepath.Join(dir, "cert.pem")
	keyFile := filepath.Join(dir, "key.pem")

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

	uploadLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		startTLSLn.Close()
		tlsLn.Close()
		tlsCtx.Close()
		t.Fatalf("listen upload: %v", err)
	}
	uploadAddr := uploadLn.Addr().String()
	uploadURL := "http://" + uploadAddr

	stores := memstore.New()
	rt := router.New()
	resumeStore := sm.NewStore(10_000)

	var secret [32]byte
	if _, err := wolfcrypt.Read(secret[:]); err != nil {
		if _, err2 := rand.Read(secret[:]); err2 != nil {
			t.Fatalf("random secret: %v", err2)
		}
	}

	uploadSvc := httpupload.New(domain, uploadURL, nil, 50<<20, secret[:], 24*time.Hour, slog.Default())
	uploadDir := filepath.Join(dir, "uploads")
	diskBackend := httpupload.NewDiskBackend(uploadDir, uploadSvc)
	uploadSvcFull := httpupload.New(domain, uploadURL, diskBackend, 50<<20, secret[:], 24*time.Hour, slog.Default())

	uploadMux := http.NewServeMux()
	uploadMux.Handle("/upload/", diskBackend.PutHandler())
	uploadMux.Handle("/download/", diskBackend.GetHandler())
	uploadSrv := &http.Server{Handler: uploadMux}
	go func() {
		if serr := uploadSrv.Serve(uploadLn); serr != nil && !errors.Is(serr, http.ErrServerClosed) {
			_ = serr
		}
	}()

	pushDisp := push.New(stores.Push, rt, domain, slog.Default())
	pushRec := &recordingProvider{}
	pushDisp.RegisterProvider("push", pushRec)

	rosterMgr := roster.New(stores.Roster, slog.Default())
	capsCache := caps.New()
	ps := pubsub.New(stores.PEP, rt, slog.Default(), 65536)
	ps.WithContactNotify(rosterMgr, capsCache)

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
		Push:       pushDisp,
		HTTPUpload: uploadSvcFull,
		PubSub:     ps,
		PEP:        pep.New(ps, slog.Default()),
		MUC:        muc.New(domain, "conference", stores.MUC, rt, slog.Default()),
		Metrics:    metrics.New(prometheus.NewRegistry()),
		SPQRPolicy: spqr.DomainPolicy{SPQROnlyMode: false},
		Caps:       capsCache,
		IBR:        ibr.New(stores, domain, allowIBR),
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
		uploadURL:  uploadURL,
		uploadSrv:  uploadSrv,
		pushRec:    pushRec,
		capsCache:  capsCache,
	}
}

func (h *Harness) TLSAddr() string {
	return h.tlsLn.Addr().String()
}

func (h *Harness) STARTTLSAddr() string {
	return h.startTLSLn.Addr().String()
}

func (h *Harness) UploadURL() string {
	return h.uploadURL
}

func (h *Harness) PushSends() []PushRecord {
	h.pushRec.mu.Lock()
	defer h.pushRec.mu.Unlock()
	cp := make([]PushRecord, len(h.pushRec.sends))
	copy(cp, h.pushRec.sends)
	return cp
}

func (h *Harness) AddUser(t *testing.T, username, password string) {
	t.Helper()
	if err := seedUser(context.Background(), h.stores, username, h.Domain, password); err != nil {
		t.Fatalf("AddUser %s: %v", username, err)
	}
}

func (h *Harness) NewClientForResume(t *testing.T, username, password string) *Client {
	t.Helper()
	c, err := dialForResume(h.TLSAddr(), h.Domain, username, password)
	if err != nil {
		t.Fatalf("NewClientForResume %s: %v", username, err)
	}
	return c
}

func (h *Harness) S2SAddr() string {
	if h.s2sLn == nil {
		return ""
	}
	return h.s2sLn.Addr()
}

// AddS2SPeer pins the s2s pool to connect to addr for domain, bypassing DNS SRV.
// Requires EnableS2S to have been set when building the harness.
func (h *Harness) AddS2SPeer(domain, addr string) {
	if h.s2sPool != nil {
		h.s2sPool.PinTarget(domain, addr)
	}
}

func (h *Harness) Close() {
	h.cancel()
	if h.s2sLn != nil {
		h.s2sLn.Close()
	}
	if h.s2sPool != nil {
		h.s2sPool.Close()
	}
	h.tlsLn.Close()
	h.startTLSLn.Close()
	h.tlsCtx.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	_ = h.uploadSrv.Shutdown(ctx)
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

func (h *Harness) Caps() *caps.Cache {
	return h.capsCache
}

func (h *Harness) AddRosterItem(t *testing.T, owner, contact string, subscription int) {
	t.Helper()
	_, err := h.stores.Roster.Put(context.Background(), &storage.RosterItem{
		Owner:        owner,
		Contact:      contact,
		Subscription: subscription,
	})
	if err != nil {
		t.Fatalf("AddRosterItem %s->%s: %v", owner, contact, err)
	}
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

