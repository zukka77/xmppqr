package c2s

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/danielinux/xmppqr/internal/auth"
	"github.com/danielinux/xmppqr/internal/carbons"
	"github.com/danielinux/xmppqr/internal/csi"
	"github.com/danielinux/xmppqr/internal/disco"
	"github.com/danielinux/xmppqr/internal/ibr"
	"github.com/danielinux/xmppqr/internal/mam"
	"github.com/danielinux/xmppqr/internal/muc"
	"github.com/danielinux/xmppqr/internal/pep"
	"github.com/danielinux/xmppqr/internal/presence"
	"github.com/danielinux/xmppqr/internal/pubsub"
	"github.com/danielinux/xmppqr/internal/roster"
	"github.com/danielinux/xmppqr/internal/router"
	"github.com/danielinux/xmppqr/internal/sm"
	"github.com/danielinux/xmppqr/internal/storage"
	"github.com/danielinux/xmppqr/internal/storage/memstore"
	"github.com/danielinux/xmppqr/internal/stanza"
	xtls "github.com/danielinux/xmppqr/internal/tls"
)

// mockTLSConn wraps net.Conn and satisfies TLSConn.
type mockTLSConn struct {
	net.Conn
}

func (m *mockTLSConn) Exporter(label string, ctx []byte, n int) ([]byte, error) {
	out := make([]byte, n)
	copy(out, []byte("fake-tls-exporter-bytes-1234"))
	return out, nil
}

func (m *mockTLSConn) HandshakeState() xtls.HandshakeState {
	return xtls.HandshakeState{Version: 0x0304}
}

// routerMockSession satisfies router.Session for routing tests.
type routerMockSession struct {
	j         stanza.JID
	available bool
	priority  int
	ch        chan []byte
}

func (m *routerMockSession) JID() stanza.JID { return m.j }
func (m *routerMockSession) Priority() int   { return m.priority }
func (m *routerMockSession) IsAvailable() bool { return m.available }
func (m *routerMockSession) Deliver(_ context.Context, raw []byte) error {
	select {
	case m.ch <- raw:
	default:
	}
	return nil
}

func makeTestConfig(stores *storage.Stores, r *router.Router, rs *sm.Store) SessionConfig {
	return SessionConfig{
		Domain:         "example.com",
		Stores:         stores,
		Router:         r,
		ResumeStore:    rs,
		MaxStanzaBytes: 1 << 20,
	}
}

func testPipe(t *testing.T) (net.Conn, net.Conn) {
	t.Helper()
	client, server := net.Pipe()
	t.Cleanup(func() { client.Close(); server.Close() })
	return client, server
}

func sendStr(t *testing.T, conn net.Conn, s string) {
	t.Helper()
	conn.SetWriteDeadline(time.Now().Add(3 * time.Second))
	if _, err := conn.Write([]byte(s)); err != nil {
		t.Fatalf("send: %v", err)
	}
}

func readUntil(t *testing.T, conn net.Conn, want string, timeout time.Duration) string {
	t.Helper()
	conn.SetReadDeadline(time.Now().Add(timeout))
	var buf strings.Builder
	tmp := make([]byte, 4096)
	for {
		n, err := conn.Read(tmp)
		if n > 0 {
			buf.Write(tmp[:n])
			if strings.Contains(buf.String(), want) {
				return buf.String()
			}
		}
		if err != nil {
			return buf.String()
		}
	}
}

func prepareUser(t *testing.T, stores *storage.Stores, username, password string) {
	t.Helper()
	salt := []byte("testsalt12345678")
	creds, err := auth.DeriveSCRAMCreds([]byte(password), salt, 4096, auth.SCRAMSHA256)
	if err != nil {
		t.Fatal(err)
	}
	u := &storage.User{
		Username:     username,
		ScramSalt:    salt,
		ScramIter:    4096,
		StoredKey256: creds.StoredKey,
		ServerKey256: creds.ServerKey,
	}
	if err := stores.Users.Put(context.Background(), u); err != nil {
		t.Fatal(err)
	}
}

// driveSCRAMSHA256 performs a SCRAM-SHA-256 exchange from the client side.
// It returns all server output collected after the final send.
func driveSCRAMSHA256(t *testing.T, client net.Conn, username, password string) string {
	t.Helper()
	clientNonce := "testclientnonce1"
	clientFirstBare := fmt.Sprintf("n=%s,r=%s", username, clientNonce)
	clientFirst := "n,," + clientFirstBare
	clientFirstB64 := base64.StdEncoding.EncodeToString([]byte(clientFirst))

	sendStr(t, client, fmt.Sprintf(
		`<authenticate xmlns='%s' mechanism='SCRAM-SHA-256'><initial-response>%s</initial-response></authenticate>`,
		nsSASL2, clientFirstB64,
	))

	raw := readUntil(t, client, "</challenge>", 3*time.Second)
	// Extract challenge base64
	challengeB64 := extractTagContent(raw, "challenge")
	if challengeB64 == "" {
		t.Fatalf("no challenge received, got: %s", raw)
	}
	challengeBytes, err := base64.StdEncoding.DecodeString(challengeB64)
	if err != nil {
		t.Fatalf("decode challenge: %v", err)
	}
	serverFirst := string(challengeBytes)

	fields := parseKVTest(serverFirst)
	saltB64 := fields["s"]
	iterStr := fields["i"]
	combinedNonce := fields["r"]
	salt, _ := base64.StdEncoding.DecodeString(saltB64)
	var iter int
	fmt.Sscanf(iterStr, "%d", &iter)

	// Re-derive from salted password
	saltedPwd, err := goSHA256PBKDF2([]byte(password), salt, iter, 32)
	if err != nil {
		t.Fatalf("pbkdf2: %v", err)
	}
	clientKey := goHMACSHA256(saltedPwd, []byte("Client Key"))
	storedKey := goSHA256(clientKey)
	serverKey := goHMACSHA256(saltedPwd, []byte("Server Key"))
	_ = serverKey

	cbindB64 := base64.StdEncoding.EncodeToString([]byte("n,,"))
	clientFinalWithoutProof := fmt.Sprintf("c=%s,r=%s", cbindB64, combinedNonce)
	authMessage := clientFirstBare + "," + serverFirst + "," + clientFinalWithoutProof

	clientSig := goHMACSHA256(storedKey[:], []byte(authMessage))
	proof := make([]byte, len(clientKey))
	for i := range clientKey {
		proof[i] = clientKey[i] ^ clientSig[i]
	}
	proofB64 := base64.StdEncoding.EncodeToString(proof)

	clientFinal := clientFinalWithoutProof + ",p=" + proofB64
	clientFinalB64 := base64.StdEncoding.EncodeToString([]byte(clientFinal))

	sendStr(t, client, fmt.Sprintf(`<response xmlns='%s'>%s</response>`, nsSASL2, clientFinalB64))

	return readUntil(t, client, "</", 3*time.Second)
}

func driveLegacySCRAMSHA256(t *testing.T, client net.Conn, username, password string) string {
	t.Helper()
	clientNonce := "testclientnonce1"
	clientFirstBare := fmt.Sprintf("n=%s,r=%s", username, clientNonce)
	clientFirst := "n,," + clientFirstBare
	clientFirstB64 := base64.StdEncoding.EncodeToString([]byte(clientFirst))

	sendStr(t, client, fmt.Sprintf(
		`<auth xmlns='%s' mechanism='SCRAM-SHA-256'>%s</auth>`,
		nsSASL, clientFirstB64,
	))

	raw := readUntil(t, client, "</challenge>", 3*time.Second)
	challengeB64 := extractTagContent(raw, "challenge")
	if challengeB64 == "" {
		t.Fatalf("no challenge received, got: %s", raw)
	}
	challengeBytes, err := base64.StdEncoding.DecodeString(challengeB64)
	if err != nil {
		t.Fatalf("decode challenge: %v", err)
	}
	serverFirst := string(challengeBytes)

	fields := parseKVTest(serverFirst)
	saltB64 := fields["s"]
	iterStr := fields["i"]
	combinedNonce := fields["r"]
	salt, _ := base64.StdEncoding.DecodeString(saltB64)
	var iter int
	fmt.Sscanf(iterStr, "%d", &iter)

	saltedPwd, err := goSHA256PBKDF2([]byte(password), salt, iter, 32)
	if err != nil {
		t.Fatalf("pbkdf2: %v", err)
	}
	clientKey := goHMACSHA256(saltedPwd, []byte("Client Key"))
	storedKey := goSHA256(clientKey)
	cbindB64 := base64.StdEncoding.EncodeToString([]byte("n,,"))
	clientFinalWithoutProof := fmt.Sprintf("c=%s,r=%s", cbindB64, combinedNonce)
	authMessage := clientFirstBare + "," + serverFirst + "," + clientFinalWithoutProof
	clientSig := goHMACSHA256(storedKey[:], []byte(authMessage))
	proof := make([]byte, len(clientKey))
	for i := range clientKey {
		proof[i] = clientKey[i] ^ clientSig[i]
	}
	proofB64 := base64.StdEncoding.EncodeToString(proof)
	clientFinal := clientFinalWithoutProof + ",p=" + proofB64
	clientFinalB64 := base64.StdEncoding.EncodeToString([]byte(clientFinal))

	sendStr(t, client, fmt.Sprintf(`<response xmlns='%s'>%s</response>`, nsSASL, clientFinalB64))
	return readUntil(t, client, "</success>", 3*time.Second)
}

func driveLegacyPlain(t *testing.T, client net.Conn, username, password string) string {
	t.Helper()
	payload := append([]byte{0}, []byte(username)...)
	payload = append(payload, 0)
	payload = append(payload, []byte(password)...)
	sendStr(t, client, fmt.Sprintf(
		`<auth xmlns='%s' mechanism='PLAIN'>%s</auth>`,
		nsSASL, base64.StdEncoding.EncodeToString(payload),
	))
	return readUntil(t, client, "</success>", 3*time.Second)
}

func extractTagContent(s, tagName string) string {
	open := "<" + tagName
	close := "</" + tagName + ">"
	start := strings.Index(s, open)
	if start < 0 {
		return ""
	}
	gt := strings.Index(s[start:], ">")
	if gt < 0 {
		return ""
	}
	content := s[start+gt+1:]
	end := strings.Index(content, close)
	if end < 0 {
		return ""
	}
	return strings.TrimSpace(content[:end])
}

func parseKVTest(s string) map[string]string {
	m := make(map[string]string)
	for _, part := range strings.Split(s, ",") {
		idx := strings.IndexByte(part, '=')
		if idx < 0 {
			continue
		}
		m[part[:idx]] = part[idx+1:]
	}
	return m
}

func TestStreamOpenAndFeatures(t *testing.T) {
	client, server := testPipe(t)
	s := NewSession(&mockTLSConn{server}, makeTestConfig(memstore.New(), router.New(), sm.NewStore(64)))

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	go s.Run(ctx)

	sendStr(t, client, `<?xml version='1.0'?><stream:stream from='user@example.com' to='example.com' version='1.0' xmlns='jabber:client' xmlns:stream='http://etherx.jabber.org/streams'>`)

	got := readUntil(t, client, "SCRAM-SHA-256", 3*time.Second)
	if !strings.Contains(got, "<stream:stream") {
		t.Errorf("missing stream header; got: %s", got)
	}
	if !strings.Contains(got, nsSASL) {
		t.Errorf("missing SASL mechanisms ns; got: %s", got)
	}
	if !strings.Contains(got, "SCRAM-SHA-256") {
		t.Errorf("missing SCRAM-SHA-256; got: %s", got)
	}
}

func TestStreamErrorOnHostUnknown(t *testing.T) {
	client, server := testPipe(t)
	s := NewSession(&mockTLSConn{server}, makeTestConfig(memstore.New(), router.New(), sm.NewStore(64)))

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	go s.Run(ctx)

	sendStr(t, client, `<stream:stream to='other.domain' xmlns='jabber:client' xmlns:stream='http://etherx.jabber.org/streams' version='1.0'>`)

	got := readUntil(t, client, "host-unknown", 3*time.Second)
	if !strings.Contains(got, "host-unknown") {
		t.Errorf("expected host-unknown; got: %s", got)
	}
}

func TestSASL2Success(t *testing.T) {
	stores := memstore.New()
	prepareUser(t, stores, "alice", "secret")

	client, server := testPipe(t)
	s := NewSession(&mockTLSConn{server}, makeTestConfig(stores, router.New(), sm.NewStore(64)))

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	go s.Run(ctx)

	sendStr(t, client, `<stream:stream to='example.com' version='1.0' xmlns='jabber:client' xmlns:stream='http://etherx.jabber.org/streams'>`)
	readUntil(t, client, "SCRAM-SHA-256", 3*time.Second)

	result := driveSCRAMSHA256(t, client, "alice", "secret")
	if !strings.Contains(result, "<success") {
		t.Errorf("expected success; got: %s", result)
	}
	if !strings.Contains(result, "alice@example.com") {
		t.Errorf("expected JID in success; got: %s", result)
	}
	if !strings.Contains(result, "<additional-data>") {
		t.Errorf("expected SCRAM server-final in SASL2 success; got: %s", result)
	}
}

func TestRunSTARTTLSUpgradeFlow(t *testing.T) {
	client, server := testPipe(t)

	prevHandshake := startTLSHandshake
	startTLSHandshake = func(_ *xtls.Context, conn net.Conn) (tlsConnIface, error) {
		return &mockTLSConn{Conn: conn}, nil
	}
	defer func() {
		startTLSHandshake = prevHandshake
	}()

	stores := memstore.New()
	prepareUser(t, stores, "alice", "secret")

	serverErr := make(chan error, 1)
	go func() {
		cfg := makeTestConfig(stores, router.New(), sm.NewStore(64))
		cfg.Logger = slog.New(slog.NewTextHandler(os.Stderr, nil))
		serverErr <- runStartTLS(context.Background(), server, nil, cfg)
	}()

	sendStr(t, client, `<?xml version='1.0'?><stream:stream from='user@example.com' to='example.com' version='1.0' xmlns='jabber:client' xmlns:stream='http://etherx.jabber.org/streams'>`)

	preTLS := readUntil(t, client, "<starttls", 3*time.Second)
	if !strings.Contains(preTLS, "<starttls xmlns='"+nsXMPPTLS+"'><required/></starttls>") {
		t.Fatalf("missing required STARTTLS feature: %s", preTLS)
	}

	sendStr(t, client, `<starttls xmlns='`+nsXMPPTLS+`'/>`)

	proceed := readUntil(t, client, "<proceed", 3*time.Second)
	if !strings.Contains(proceed, "<proceed xmlns='"+nsXMPPTLS+"'/>") {
		t.Fatalf("missing proceed response: %s", proceed)
	}

	sendStr(t, client, `<?xml version='1.0'?><stream:stream from='user@example.com' to='example.com' version='1.0' xmlns='jabber:client' xmlns:stream='http://etherx.jabber.org/streams'>`)

	postTLS := readUntil(t, client, "SCRAM-SHA-256", 3*time.Second)
	if !strings.Contains(postTLS, nsSASL) {
		t.Fatalf("missing post-STARTTLS SASL features: %s", postTLS)
	}

	_ = client.Close()
	if err := <-serverErr; err != nil && !errors.Is(err, io.EOF) {
		t.Fatalf("RunSTARTTLS: %v", err)
	}
}

func TestSASL2Failure(t *testing.T) {
	stores := memstore.New()
	prepareUser(t, stores, "bob", "correctpassword")

	client, server := testPipe(t)
	s := NewSession(&mockTLSConn{server}, makeTestConfig(stores, router.New(), sm.NewStore(64)))

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	go s.Run(ctx)

	sendStr(t, client, `<stream:stream to='example.com' version='1.0' xmlns='jabber:client' xmlns:stream='http://etherx.jabber.org/streams'>`)
	readUntil(t, client, "SCRAM-SHA-256", 3*time.Second)

	result := driveSCRAMSHA256(t, client, "bob", "wrongpassword")
	if !strings.Contains(result, "failure") && !strings.Contains(result, "not-authorized") {
		t.Errorf("expected failure; got: %s", result)
	}
}

func TestLegacySASLSuccessAndBind(t *testing.T) {
	stores := memstore.New()
	prepareUser(t, stores, "dino", "secret")

	client, server := testPipe(t)
	s := NewSession(&mockTLSConn{server}, makeTestConfig(stores, router.New(), sm.NewStore(64)))

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	go s.Run(ctx)

	sendStr(t, client, `<stream:stream to='example.com' version='1.0' xmlns='jabber:client' xmlns:stream='http://etherx.jabber.org/streams'>`)
	readUntil(t, client, "SCRAM-SHA-256", 3*time.Second)

	result := driveLegacySCRAMSHA256(t, client, "dino", "secret")
	if !strings.Contains(result, "<success") {
		t.Fatalf("expected success; got: %s", result)
	}
	if strings.Contains(result, "<additional-data>") {
		t.Fatalf("legacy SASL success should contain raw base64 payload, got: %s", result)
	}

	sendStr(t, client, `<stream:stream to='example.com' version='1.0' xmlns='jabber:client' xmlns:stream='http://etherx.jabber.org/streams'>`)
	postAuth := readUntil(t, client, "urn:ietf:params:xml:ns:xmpp-bind", 3*time.Second)
	if !strings.Contains(postAuth, "urn:ietf:params:xml:ns:xmpp-bind") {
		t.Fatalf("expected post-auth bind features; got: %s", postAuth)
	}

	sendStr(t, client, `<iq id='bind1' type='set'><bind xmlns='urn:ietf:params:xml:ns:xmpp-bind'/></iq>`)
	bindResp := readUntil(t, client, "<jid>", 3*time.Second)
	if !strings.Contains(bindResp, "<iq id='bind1' type='result'>") {
		t.Fatalf("expected bind result; got: %s", bindResp)
	}
}

func TestLegacyPlainSuccessAndBind(t *testing.T) {
	stores := memstore.New()
	prepareUser(t, stores, "plainuser", "secret")
	u, err := stores.Users.Get(context.Background(), "plainuser")
	if err != nil {
		t.Fatal(err)
	}
	u.Argon2Params, err = auth.HashPasswordForStorage([]byte("secret"))
	if err != nil {
		t.Fatal(err)
	}
	if err := stores.Users.Put(context.Background(), u); err != nil {
		t.Fatal(err)
	}

	client, server := testPipe(t)
	s := NewSession(&mockTLSConn{server}, makeTestConfig(stores, router.New(), sm.NewStore(64)))

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	go s.Run(ctx)

	sendStr(t, client, `<stream:stream to='example.com' version='1.0' xmlns='jabber:client' xmlns:stream='http://etherx.jabber.org/streams'>`)
	features := readUntil(t, client, "PLAIN", 3*time.Second)
	if !strings.Contains(features, "PLAIN") {
		t.Fatalf("expected PLAIN in mechanisms: %s", features)
	}

	result := driveLegacyPlain(t, client, "plainuser", "secret")
	if !strings.Contains(result, "<success") {
		t.Fatalf("expected success; got: %s", result)
	}

	sendStr(t, client, `<stream:stream to='example.com' version='1.0' xmlns='jabber:client' xmlns:stream='http://etherx.jabber.org/streams'>`)
	postAuth := readUntil(t, client, "urn:ietf:params:xml:ns:xmpp-bind", 3*time.Second)
	if !strings.Contains(postAuth, "urn:ietf:params:xml:ns:xmpp-bind") {
		t.Fatalf("expected post-auth bind features; got: %s", postAuth)
	}
}

func TestBind2InlineSM(t *testing.T) {
	stores := memstore.New()
	prepareUser(t, stores, "charlie", "pass123")

	client, server := testPipe(t)
	s := NewSession(&mockTLSConn{server}, makeTestConfig(stores, router.New(), sm.NewStore(64)))

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	go s.Run(ctx)

	sendStr(t, client, `<stream:stream to='example.com' version='1.0' xmlns='jabber:client' xmlns:stream='http://etherx.jabber.org/streams'>`)
	readUntil(t, client, "SCRAM-SHA-256", 3*time.Second)

	result := driveSCRAMSHA256(t, client, "charlie", "pass123")
	if !strings.Contains(result, "<success") {
		t.Errorf("expected success; got: %s", result)
	}
	// Verify jid was assigned
	if s.jid.Local == "" {
		t.Error("session JID not set after auth")
	}
	if s.jid.Resource == "" {
		t.Error("session resource not allocated after bind")
	}
}

// authenticateSession drives a full SASL2 auth and returns the client conn ready for stanzas.
func authenticateSession(t *testing.T, stores *storage.Stores, mods *Modules, username, password string) (net.Conn, context.CancelFunc) {
	t.Helper()
	r := router.New()
	rs := sm.NewStore(64)
	cfg := SessionConfig{
		Domain:         "example.com",
		Stores:         stores,
		Router:         r,
		ResumeStore:    rs,
		MaxStanzaBytes: 1 << 20,
		Modules:        mods,
	}
	client, server := testPipe(t)
	s := NewSession(&mockTLSConn{server}, cfg)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	go s.Run(ctx)
	sendStr(t, client, `<stream:stream to='example.com' version='1.0' xmlns='jabber:client' xmlns:stream='http://etherx.jabber.org/streams'>`)
	readUntil(t, client, "SCRAM-SHA-256", 3*time.Second)
	result := driveSCRAMSHA256(t, client, username, password)
	if !strings.Contains(result, "<success") {
		t.Fatalf("auth failed: %s", result)
	}
	time.Sleep(20 * time.Millisecond)
	return client, cancel
}

func TestPingIQ(t *testing.T) {
	stores := memstore.New()
	prepareUser(t, stores, "pinguser", "pass")
	client, cancel := authenticateSession(t, stores, nil, "pinguser", "pass")
	defer cancel()

	sendStr(t, client, `<iq id='1' type='get'><ping xmlns='urn:xmpp:ping'/></iq>`)
	got := readUntil(t, client, "result", 3*time.Second)
	if !strings.Contains(got, "1") || !strings.Contains(got, "result") {
		t.Errorf("expected ping result; got: %s", got)
	}
}

func TestUnknownIQNamespace(t *testing.T) {
	stores := memstore.New()
	prepareUser(t, stores, "unkuser", "pass")
	client, cancel := authenticateSession(t, stores, nil, "unkuser", "pass")
	defer cancel()

	sendStr(t, client, `<iq id='2' type='get'><query xmlns='urn:example:unknown'/></iq>`)
	got := readUntil(t, client, "feature-not-implemented", 3*time.Second)
	if !strings.Contains(got, "feature-not-implemented") {
		t.Errorf("expected feature-not-implemented; got: %s", got)
	}
}

func TestDiscoInfo(t *testing.T) {
	stores := memstore.New()
	prepareUser(t, stores, "discouser", "pass")
	mods := &Modules{Disco: disco.DefaultServer()}
	client, cancel := authenticateSession(t, stores, mods, "discouser", "pass")
	defer cancel()

	sendStr(t, client, `<iq id='3' type='get'><query xmlns='http://jabber.org/protocol/disco#info'/></iq>`)
	got := readUntil(t, client, "</query>", 3*time.Second)
	if !strings.Contains(got, "<identity") {
		t.Errorf("expected identity element; got: %s", got)
	}
	if !strings.Contains(got, "<feature") {
		t.Errorf("expected feature elements; got: %s", got)
	}
}

func TestStanzaRouting(t *testing.T) {
	stores := memstore.New()
	prepareUser(t, stores, "dave", "pass")

	r := router.New()
	rs := sm.NewStore(64)

	delivered := make(chan []byte, 4)
	targetJID, _ := stanza.Parse("eve@example.com/res1")
	target := &routerMockSession{
		j:         targetJID,
		available: true,
		ch:        delivered,
	}
	r.Register(target)
	defer r.Unregister(target)

	client, server := testPipe(t)
	sess := NewSession(&mockTLSConn{server}, makeTestConfig(stores, r, rs))

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	go sess.Run(ctx)

	sendStr(t, client, `<stream:stream to='example.com' version='1.0' xmlns='jabber:client' xmlns:stream='http://etherx.jabber.org/streams'>`)
	readUntil(t, client, "SCRAM-SHA-256", 3*time.Second)
	driveSCRAMSHA256(t, client, "dave", "pass")

	// Give writer goroutine a moment to start
	time.Sleep(50 * time.Millisecond)

	sendStr(t, client, `<message to='eve@example.com' xmlns='jabber:client'><body>hello</body></message>`)

	select {
	case raw := <-delivered:
		if !strings.Contains(string(raw), "hello") {
			t.Errorf("unexpected delivery content: %s", raw)
		}
	case <-time.After(3 * time.Second):
		t.Error("timeout waiting for routed message")
	}
}

func TestBindIQNamespacePrecise(t *testing.T) {
	stores := memstore.New()
	prepareUser(t, stores, "bindtest", "pass")
	client, cancel := authenticateSession(t, stores, nil, "bindtest", "pass")
	defer cancel()

	sendStr(t, client, `<iq id='b1' type='set'><other xmlns='something:that:contains:urn:xmpp:bind:0'/></iq>`)
	got := readUntil(t, client, "feature-not-implemented", 3*time.Second)
	if !strings.Contains(got, "feature-not-implemented") {
		t.Errorf("expected feature-not-implemented for non-bind ns; got: %s", got)
	}
}

func TestBookmarksViaPubSub(t *testing.T) {
	stores := memstore.New()
	prepareUser(t, stores, "bookmarkuser", "pass")

	ps := pubsub.New(stores.PEP, router.New(), slog.Default(), 0)
	mods := &Modules{PubSub: ps}
	client, cancel := authenticateSession(t, stores, mods, "bookmarkuser", "pass")
	defer cancel()

	publishIQ := `<iq id='bm1' type='set'>` +
		`<pubsub xmlns='http://jabber.org/protocol/pubsub'>` +
		`<publish node='urn:xmpp:bookmarks:1'>` +
		`<item id='room@conf.example'>` +
		`<conference xmlns='urn:xmpp:bookmarks:1' name='Cool Room' autojoin='true'/>` +
		`</item>` +
		`</publish>` +
		`</pubsub>` +
		`</iq>`
	sendStr(t, client, publishIQ)
	got := readUntil(t, client, `type="result"`, 3*time.Second)
	if !strings.Contains(got, `type="result"`) {
		t.Fatalf("expected pubsub publish result; got: %s", got)
	}

	items, err := stores.PEP.ListItems(context.Background(), "bookmarkuser@example.com", "urn:xmpp:bookmarks:1", 0)
	if err != nil {
		t.Fatalf("list items: %v", err)
	}
	if len(items) != 1 {
		t.Fatalf("expected 1 stored bookmark, got %d", len(items))
	}

	getIQ := `<iq id='bm2' type='get'>` +
		`<pubsub xmlns='http://jabber.org/protocol/pubsub'>` +
		`<items node='urn:xmpp:bookmarks:1'/>` +
		`</pubsub>` +
		`</iq>`
	sendStr(t, client, getIQ)
	got2 := readUntil(t, client, "room@conf.example", 3*time.Second)
	if !strings.Contains(got2, "room@conf.example") {
		t.Errorf("expected bookmark item in items response; got: %s", got2)
	}
}

// authenticateSessionWithRouter is like authenticateSession but uses the provided shared router.
func authenticateSessionWithRouter(t *testing.T, stores *storage.Stores, mods *Modules, r *router.Router, username, password string) (net.Conn, context.CancelFunc) {
	t.Helper()
	rs := sm.NewStore(64)
	cfg := SessionConfig{
		Domain:         "example.com",
		Stores:         stores,
		Router:         r,
		ResumeStore:    rs,
		MaxStanzaBytes: 1 << 20,
		Modules:        mods,
	}
	client, server := testPipe(t)
	s := NewSession(&mockTLSConn{server}, cfg)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	go s.Run(ctx)
	sendStr(t, client, `<stream:stream to='example.com' version='1.0' xmlns='jabber:client' xmlns:stream='http://etherx.jabber.org/streams'>`)
	readUntil(t, client, "SCRAM-SHA-256", 3*time.Second)
	result := driveSCRAMSHA256(t, client, username, password)
	if !strings.Contains(result, "<success") {
		t.Fatalf("auth failed: %s", result)
	}
	time.Sleep(20 * time.Millisecond)
	return client, cancel
}

func TestMAMArchivedOnSend(t *testing.T) {
	stores := memstore.New()
	prepareUser(t, stores, "alice", "pass")

	mamSvc := mam.New(stores.MAM, slog.Default())
	mods := &Modules{MAM: mamSvc}

	r := router.New()
	target := &routerMockSession{
		j:         func() stanza.JID { j, _ := stanza.Parse("bob@example.com/r1"); return j }(),
		available: true,
		ch:        make(chan []byte, 4),
	}
	r.Register(target)
	defer r.Unregister(target)

	client, cancel := authenticateSessionWithRouter(t, stores, mods, r, "alice", "pass")
	defer cancel()

	sendStr(t, client, `<message to='bob@example.com' xmlns='jabber:client'><body>hi</body></message>`)
	time.Sleep(100 * time.Millisecond)

	select {
	case delivered := <-target.ch:
		got := string(delivered)
		if !strings.Contains(got, "from='alice@example.com/") && !strings.Contains(got, `from="alice@example.com/`) {
			t.Fatalf("expected routed message from alice resource, got: %s", got)
		}
		if !strings.Contains(got, "to='bob@example.com'") && !strings.Contains(got, `to="bob@example.com"`) {
			t.Fatalf("expected routed message to bob, got: %s", got)
		}
	default:
		t.Fatal("expected routed message delivery")
	}

	archived, err := stores.MAM.Query(context.Background(), "alice@example.com", nil, nil, nil, 10)
	if err != nil {
		t.Fatalf("mam query: %v", err)
	}
	if len(archived) != 1 {
		t.Fatalf("expected 1 archived message, got %d", len(archived))
	}
}

func TestRosterIQGet(t *testing.T) {
	stores := memstore.New()
	prepareUser(t, stores, "rosteruser", "pass")

	rm := roster.New(stores.Roster, slog.Default())
	ctx := context.Background()
	owner := "rosteruser@example.com"
	_, _ = rm.Set(ctx, owner, func() stanza.JID { j, _ := stanza.Parse("alice@example.com"); return j }(), "Alice", nil)
	_, _ = rm.Set(ctx, owner, func() stanza.JID { j, _ := stanza.Parse("bob@example.com"); return j }(), "Bob", nil)

	mods := &Modules{Roster: rm}
	client, cancel := authenticateSession(t, stores, mods, "rosteruser", "pass")
	defer cancel()

	sendStr(t, client, `<iq id='r1' type='get'><query xmlns='jabber:iq:roster'/></iq>`)
	got := readUntil(t, client, "</query>", 3*time.Second)
	if !strings.Contains(got, "alice@example.com") {
		t.Errorf("expected alice in roster response; got: %s", got)
	}
	if !strings.Contains(got, "bob@example.com") {
		t.Errorf("expected bob in roster response; got: %s", got)
	}
}

func TestPresenceSubscribeForwarded(t *testing.T) {
	stores := memstore.New()
	prepareUser(t, stores, "alice", "pass")

	rm := roster.New(stores.Roster, slog.Default())
	mods := &Modules{Roster: rm}

	r := router.New()
	received := make(chan []byte, 4)
	bobJID, _ := stanza.Parse("bob@example.com/r1")
	bobSess := &routerMockSession{j: bobJID, available: true, ch: received}
	r.Register(bobSess)
	defer r.Unregister(bobSess)

	client, cancel := authenticateSessionWithRouter(t, stores, mods, r, "alice", "pass")
	defer cancel()

	sendStr(t, client, `<presence to='bob@example.com' type='subscribe' xmlns='jabber:client'/>`)

	select {
	case raw := <-received:
		if !strings.Contains(string(raw), "subscribe") {
			t.Errorf("expected subscribe presence; got: %s", raw)
		}
	case <-time.After(3 * time.Second):
		t.Error("timeout: subscribe presence not routed")
	}

	items, _, err := stores.Roster.Get(context.Background(), "alice@example.com")
	if err != nil {
		t.Fatalf("roster get: %v", err)
	}
	found := false
	for _, item := range items {
		if item.Contact == "bob@example.com" && item.Ask == 1 {
			found = true
		}
	}
	if !found {
		t.Errorf("expected ask=subscribe in alice's roster for bob")
	}
}

func TestReplayOfflineMessagesDeliversQueuedStanzas(t *testing.T) {
	stores := memstore.New()
	ctx := context.Background()
	_, err := stores.Offline.Push(ctx, &storage.OfflineMessage{
		Owner:  "alice@example.com",
		TS:     time.Now().UTC(),
		Stanza: []byte("<message from='bob@example.com' to='alice@example.com'><body>queued</body></message>"),
	})
	if err != nil {
		t.Fatalf("push offline: %v", err)
	}

	s := &Session{
		cfg: SessionConfig{Stores: stores},
		jid: stanza.JID{Local: "alice", Domain: "example.com", Resource: "phone"},
		outbound: make(chan []byte, 4),
		csiF: csi.New(),
		done: make(chan struct{}),
	}

	s.replayOfflineMessages(ctx)

	select {
	case raw := <-s.outbound:
		if !bytes.Contains(raw, []byte("queued")) {
			t.Fatalf("expected queued message body, got %s", raw)
		}
	default:
		t.Fatal("expected offline message to be replayed")
	}

	n, err := stores.Offline.Count(ctx, "alice@example.com")
	if err != nil {
		t.Fatalf("count offline: %v", err)
	}
	if n != 0 {
		t.Fatalf("expected offline queue drained, got %d remaining", n)
	}
}

func TestCarbonsEnableThenDeliver(t *testing.T) {
	// Tests SessionsFor + carbons fan-out at the router level using mock sessions.
	r := router.New()

	alice1JID, _ := stanza.Parse("alice@example.com/phone")
	alice2JID, _ := stanza.Parse("alice@example.com/laptop")

	ch1 := make(chan []byte, 8)
	ch2 := make(chan []byte, 8)
	sess1 := &routerMockSession{j: alice1JID, available: true, ch: ch1}
	sess2 := &routerMockSession{j: alice2JID, available: true, ch: ch2}
	r.Register(sess1)
	r.Register(sess2)
	defer r.Unregister(sess1)
	defer r.Unregister(sess2)

	cm := carbons.New(r, slog.Default())
	cm.EnableForSession(alice2JID)

	allRes := r.SessionsFor("alice@example.com")
	jids := make([]stanza.JID, 0, len(allRes))
	for _, s := range allRes {
		jids = append(jids, s.JID())
	}

	originalMsg := []byte(`<message from='bob@example.com' to='alice@example.com/phone'><body>hello</body></message>`)
	_ = cm.DeliverCarbons(context.Background(), alice1JID.Bare(), alice1JID, originalMsg, 0, jids)

	select {
	case raw := <-ch2:
		if !strings.Contains(string(raw), "received") {
			t.Errorf("expected <received> carbon on laptop; got: %s", raw)
		}
	case <-time.After(2 * time.Second):
		t.Error("timeout: carbon not delivered to laptop session")
	}

	select {
	case <-ch1:
		t.Error("phone session should not receive a carbon copy of its own original")
	default:
	}
}

func TestPEPPublishFromAuthenticatedSession(t *testing.T) {
	stores := memstore.New()
	prepareUser(t, stores, "pepuser", "pass")

	r := router.New()
	ps := pubsub.New(stores.PEP, r, slog.Default(), 0)
	pepSvc := pep.New(ps, slog.Default())
	mods := &Modules{PEP: pepSvc, PubSub: ps}

	client, cancel := authenticateSessionWithRouter(t, stores, mods, r, "pepuser", "pass")
	defer cancel()

	publishIQ := `<iq id='omemo1' type='set'>` +
		`<pubsub xmlns='http://jabber.org/protocol/pubsub'>` +
		`<publish node='eu.siacs.conversations.axolotl.devicelist'>` +
		`<item id='current'>` +
		`<list xmlns='eu.siacs.conversations.axolotl'><device id='1234567'/></list>` +
		`</item>` +
		`</publish>` +
		`</pubsub>` +
		`</iq>`
	sendStr(t, client, publishIQ)
	got := readUntil(t, client, `type="result"`, 3*time.Second)
	if !strings.Contains(got, `type="result"`) {
		t.Fatalf("expected publish result; got: %s", got)
	}

	fetchIQ := `<iq id='omemo2' type='get'>` +
		`<pubsub xmlns='http://jabber.org/protocol/pubsub'>` +
		`<items node='eu.siacs.conversations.axolotl.devicelist' max_items='1'/>` +
		`</pubsub>` +
		`</iq>`
	sendStr(t, client, fetchIQ)
	got2 := readUntil(t, client, "1234567", 3*time.Second)
	if !strings.Contains(got2, "1234567") {
		t.Fatalf("expected device id in fetch response; got: %s", got2)
	}
}

func TestLegacySessionIQ(t *testing.T) {
	stores := memstore.New()
	prepareUser(t, stores, "sessuser", "pass")
	client, cancel := authenticateSession(t, stores, nil, "sessuser", "pass")
	defer cancel()

	sendStr(t, client, `<iq id='sess1' type='set'><session xmlns='urn:ietf:params:xml:ns:xmpp-session'/></iq>`)
	got := readUntil(t, client, "result", 3*time.Second)
	if !strings.Contains(got, "sess1") || !strings.Contains(got, "result") {
		t.Errorf("expected empty result for session IQ; got: %s", got)
	}
	if strings.Contains(got, "error") {
		t.Errorf("unexpected error in session IQ response; got: %s", got)
	}
}

func TestVersionIQ(t *testing.T) {
	stores := memstore.New()
	prepareUser(t, stores, "veruser", "pass")
	client, cancel := authenticateSession(t, stores, nil, "veruser", "pass")
	defer cancel()

	sendStr(t, client, `<iq id='ver1' type='get'><query xmlns='jabber:iq:version'/></iq>`)
	got := readUntil(t, client, "</query>", 3*time.Second)
	if !strings.Contains(got, "xmppqr") {
		t.Errorf("expected name in version response; got: %s", got)
	}
	if !strings.Contains(got, "<version>") {
		t.Errorf("expected version element; got: %s", got)
	}
	if !strings.Contains(got, "<os>") {
		t.Errorf("expected os element; got: %s", got)
	}
}

func TestEntityTimeIQ(t *testing.T) {
	stores := memstore.New()
	prepareUser(t, stores, "timeuser", "pass")
	client, cancel := authenticateSession(t, stores, nil, "timeuser", "pass")
	defer cancel()

	sendStr(t, client, `<iq id='time1' type='get'><time xmlns='urn:xmpp:time'/></iq>`)
	got := readUntil(t, client, "</time>", 3*time.Second)
	if !strings.Contains(got, "<tzo>") {
		t.Errorf("expected tzo element; got: %s", got)
	}
	if !strings.Contains(got, "<utc>") {
		t.Errorf("expected utc element; got: %s", got)
	}
	if !strings.Contains(got, "+00:00") {
		t.Errorf("expected +00:00 tzo; got: %s", got)
	}
}

func TestLastActivityIQ(t *testing.T) {
	stores := memstore.New()
	prepareUser(t, stores, "lastuser", "pass")
	client, cancel := authenticateSession(t, stores, nil, "lastuser", "pass")
	defer cancel()

	sendStr(t, client, `<iq id='last1' type='get'><query xmlns='jabber:iq:last'/></iq>`)
	got := readUntil(t, client, "seconds=", 3*time.Second)
	if !strings.Contains(got, "seconds=") {
		t.Errorf("expected seconds attribute; got: %s", got)
	}
	if strings.Contains(got, "seconds='-") {
		t.Errorf("expected non-negative seconds; got: %s", got)
	}
}

func TestPEPNotifyOwnerResources(t *testing.T) {
	stores := memstore.New()
	prepareUser(t, stores, "notifyuser", "pass")

	r := router.New()
	ps := pubsub.New(stores.PEP, r, slog.Default(), 0)
	pepSvc := pep.New(ps, slog.Default())
	mods := &Modules{PEP: pepSvc, PubSub: ps}

	client1, cancel1 := authenticateSessionWithRouter(t, stores, mods, r, "notifyuser", "pass")
	defer cancel1()

	notifyCh := make(chan []byte, 8)
	res2JID, _ := stanza.Parse("notifyuser@example.com/res2")
	mockSess := &routerMockSession{j: res2JID, available: true, ch: notifyCh}
	r.Register(mockSess)
	defer r.Unregister(mockSess)

	publishIQ := `<iq id='omemo3' type='set'>` +
		`<pubsub xmlns='http://jabber.org/protocol/pubsub'>` +
		`<publish node='eu.siacs.conversations.axolotl.devicelist'>` +
		`<item id='current'>` +
		`<list xmlns='eu.siacs.conversations.axolotl'><device id='9999'/></list>` +
		`</item>` +
		`</publish>` +
		`</pubsub>` +
		`</iq>`
	sendStr(t, client1, publishIQ)
	readUntil(t, client1, `type="result"`, 3*time.Second)

	select {
	case raw := <-notifyCh:
		if !strings.Contains(string(raw), "9999") {
			t.Errorf("notify to second resource missing device id; got: %s", raw)
		}
		if !strings.Contains(string(raw), "event") {
			t.Errorf("notify missing event element; got: %s", raw)
		}
	case <-time.After(3 * time.Second):
		t.Error("timeout: notify not delivered to second resource")
	}
}

func TestSubscribeFlow(t *testing.T) {
	stores := memstore.New()
	prepareUser(t, stores, "alice", "pass")

	rm := roster.New(stores.Roster, slog.Default())
	mods := &Modules{Roster: rm}

	r := router.New()

	bobReceived := make(chan []byte, 4)
	aliceOtherReceived := make(chan []byte, 8)

	bobJID, _ := stanza.Parse("bob@example.com/r1")
	bobSess := &routerMockSession{j: bobJID, available: true, ch: bobReceived}
	r.Register(bobSess)
	defer r.Unregister(bobSess)

	client, cancel := authenticateSessionWithRouter(t, stores, mods, r, "alice", "pass")
	defer cancel()
	time.Sleep(30 * time.Millisecond)

	// Register a second Alice resource to receive roster push.
	aliceOtherJID, _ := stanza.Parse("alice@example.com/phone")
	aliceOther := &routerMockSession{j: aliceOtherJID, available: true, ch: aliceOtherReceived}
	r.Register(aliceOther)
	defer r.Unregister(aliceOther)

	sendStr(t, client, `<presence to='bob@example.com' type='subscribe' xmlns='jabber:client'/>`)

	select {
	case raw := <-bobReceived:
		if !strings.Contains(string(raw), "subscribe") {
			t.Errorf("expected subscribe presence at Bob; got: %s", raw)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("timeout: subscribe not routed to Bob")
	}

	select {
	case raw := <-aliceOtherReceived:
		if !strings.Contains(string(raw), "jabber:iq:roster") {
			t.Errorf("expected roster push at Alice's second resource; got: %s", raw)
		}
		if !strings.Contains(string(raw), "bob@example.com") {
			t.Errorf("roster push missing Bob's JID; got: %s", raw)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("timeout: roster push not delivered to Alice's second resource")
	}

	items, _, err := stores.Roster.Get(context.Background(), "alice@example.com")
	if err != nil {
		t.Fatalf("roster get: %v", err)
	}
	found := false
	for _, item := range items {
		if item.Contact == "bob@example.com" && item.Ask == 1 {
			found = true
		}
	}
	if !found {
		t.Error("expected ask=subscribe in Alice's roster for Bob")
	}
}

func TestSubscribedReturnsCurrentPresence(t *testing.T) {
	stores := memstore.New()
	prepareUser(t, stores, "alice", "pass")

	rm := roster.New(stores.Roster, slog.Default())
	ctx := context.Background()
	// Pre-create a pending subscription entry (Alice subscribed to Bob, Bob has not approved yet).
	_, _ = stores.Roster.Put(ctx, &storage.RosterItem{
		Owner:        "alice@example.com",
		Contact:      "bob@example.com",
		Subscription: 0,
		Ask:          1,
	})

	mods := &Modules{Roster: rm}
	r := router.New()

	bobReceived := make(chan []byte, 8)
	bobJID, _ := stanza.Parse("bob@example.com/r1")
	bobSess := &routerMockSession{j: bobJID, available: true, ch: bobReceived}
	r.Register(bobSess)
	defer r.Unregister(bobSess)

	client, cancel := authenticateSessionWithRouter(t, stores, mods, r, "alice", "pass")
	defer cancel()
	time.Sleep(30 * time.Millisecond)

	// Make Alice available so currentAvailablePresence() can find her session.
	sendStr(t, client, `<presence xmlns='jabber:client'/>`)
	time.Sleep(30 * time.Millisecond)
	// Drain any presence broadcast that might have gone to Bob (none expected since Bob's
	// subscription is 'none' at this point, but drain anyway).
	for len(bobReceived) > 0 {
		<-bobReceived
	}

	// Alice sends subscribed to Bob — she is approving Bob's inbound subscribe.
	sendStr(t, client, `<presence to='bob@example.com' type='subscribed' xmlns='jabber:client'/>`)

	// Expect the 'subscribed' stanza itself.
	gotSubscribed := false
	gotPresence := false
	deadline := time.After(3 * time.Second)
	for i := 0; i < 2; i++ {
		select {
		case raw := <-bobReceived:
			s := string(raw)
			if strings.Contains(s, "subscribed") {
				gotSubscribed = true
			}
			if !strings.Contains(s, "subscribed") && !strings.Contains(s, "unsubscribed") {
				gotPresence = true
			}
		case <-deadline:
			t.Fatal("timeout waiting for stanzas at Bob")
		}
	}
	if !gotSubscribed {
		t.Error("Bob did not receive 'subscribed' presence")
	}
	if !gotPresence {
		t.Error("Bob did not receive Alice's current available presence")
	}
}

func TestUnsubscribeUpdatesRoster(t *testing.T) {
	stores := memstore.New()
	prepareUser(t, stores, "alice", "pass")

	rm := roster.New(stores.Roster, slog.Default())
	ctx := context.Background()
	// Start from both: Alice is subscribed to Bob and Bob to Alice.
	_, _ = stores.Roster.Put(ctx, &storage.RosterItem{
		Owner:        "alice@example.com",
		Contact:      "bob@example.com",
		Subscription: 3, // both
		Ask:          0,
	})

	mods := &Modules{Roster: rm}
	r := router.New()

	bobReceived := make(chan []byte, 4)
	bobJID, _ := stanza.Parse("bob@example.com/r1")
	bobSess := &routerMockSession{j: bobJID, available: true, ch: bobReceived}
	r.Register(bobSess)
	defer r.Unregister(bobSess)

	client, cancel := authenticateSessionWithRouter(t, stores, mods, r, "alice", "pass")
	defer cancel()
	time.Sleep(30 * time.Millisecond)

	sendStr(t, client, `<presence to='bob@example.com' type='unsubscribe' xmlns='jabber:client'/>`)

	select {
	case raw := <-bobReceived:
		if !strings.Contains(string(raw), "unsubscribe") {
			t.Errorf("expected unsubscribe at Bob; got: %s", raw)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("timeout: unsubscribe not routed to Bob")
	}

	items, _, err := stores.Roster.Get(ctx, "alice@example.com")
	if err != nil {
		t.Fatalf("roster get: %v", err)
	}
	if len(items) != 1 {
		t.Fatalf("expected 1 roster item, got %d", len(items))
	}
	if items[0].Subscription != 1 {
		t.Errorf("expected subscription=from (1) after unsubscribe from both, got %d", items[0].Subscription)
	}
}

func TestInitialPresenceBroadcastToContacts(t *testing.T) {
	stores := memstore.New()
	prepareUser(t, stores, "alice", "pass")

	rm := roster.New(stores.Roster, slog.Default())
	ctx := context.Background()
	// Bob is subscribed from Alice (Alice has subscription=from for Bob).
	_, _ = stores.Roster.Put(ctx, &storage.RosterItem{
		Owner:        "alice@example.com",
		Contact:      "bob@example.com",
		Subscription: 1, // from
		Ask:          0,
	})

	r := router.New()
	pb := presence.New(r, rm, slog.Default())
	mods := &Modules{Roster: rm, Presence: pb}

	bobReceived := make(chan []byte, 4)
	bobJID, _ := stanza.Parse("bob@example.com/r1")
	bobSess := &routerMockSession{j: bobJID, available: true, ch: bobReceived}
	r.Register(bobSess)
	defer r.Unregister(bobSess)

	client, cancel := authenticateSessionWithRouter(t, stores, mods, r, "alice", "pass")
	defer cancel()
	time.Sleep(30 * time.Millisecond)

	sendStr(t, client, `<presence xmlns='jabber:client'/>`)

	select {
	case raw := <-bobReceived:
		s := string(raw)
		if strings.Contains(s, "subscribe") || strings.Contains(s, "unavailable") {
			t.Errorf("unexpected presence type at Bob; got: %s", s)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("timeout: Alice's initial presence not broadcasted to Bob")
	}
}

func driveIBRPreAuth(t *testing.T, client net.Conn, username, password string) string {
	t.Helper()
	iq := fmt.Sprintf(
		`<iq id='reg1' type='set'><query xmlns='jabber:iq:register'><username>%s</username><password>%s</password></query></iq>`,
		username, password,
	)
	sendStr(t, client, iq)
	return readUntil(t, client, "</iq>", 3*time.Second)
}

func TestIBREnabledAndDisabled(t *testing.T) {
	t.Run("enabled creates user", func(t *testing.T) {
		stores := memstore.New()
		ibrSvc := ibr.New(stores, "example.com", true)
		mods := &Modules{IBR: ibrSvc}

		client, server := testPipe(t)
		cfg := SessionConfig{
			Domain:         "example.com",
			Stores:         stores,
			Router:         router.New(),
			ResumeStore:    sm.NewStore(64),
			MaxStanzaBytes: 1 << 20,
			Modules:        mods,
		}
		s := NewSession(&mockTLSConn{server}, cfg)
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		go s.Run(ctx)

		sendStr(t, client, `<stream:stream to='example.com' version='1.0' xmlns='jabber:client' xmlns:stream='http://etherx.jabber.org/streams'>`)
		features := readUntil(t, client, "iq-register", 3*time.Second)
		if !strings.Contains(features, "iq-register") {
			t.Fatalf("expected iq-register feature; got: %s", features)
		}

		result := driveIBRPreAuth(t, client, "newuser", "securepassword")
		if !strings.Contains(result, `type='result'`) && !strings.Contains(result, `type="result"`) {
			t.Fatalf("expected result IQ after registration; got: %s", result)
		}

		u, err := stores.Users.Get(context.Background(), "newuser@example.com")
		if err != nil || u == nil {
			t.Fatalf("user not created: err=%v user=%v", err, u)
		}
	})

	t.Run("disabled returns not-allowed", func(t *testing.T) {
		stores := memstore.New()
		ibrSvc := ibr.New(stores, "example.com", false)
		mods := &Modules{IBR: ibrSvc}

		client, server := testPipe(t)
		cfg := SessionConfig{
			Domain:         "example.com",
			Stores:         stores,
			Router:         router.New(),
			ResumeStore:    sm.NewStore(64),
			MaxStanzaBytes: 1 << 20,
			Modules:        mods,
		}
		s := NewSession(&mockTLSConn{server}, cfg)
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		go s.Run(ctx)

		sendStr(t, client, `<stream:stream to='example.com' version='1.0' xmlns='jabber:client' xmlns:stream='http://etherx.jabber.org/streams'>`)
		features := readUntil(t, client, "</stream:features>", 3*time.Second)
		if strings.Contains(features, "iq-register") {
			t.Errorf("should not advertise iq-register when disabled; got: %s", features)
		}
	})
}

func TestMUCJoinConflictReturnsPresenceError(t *testing.T) {
	ctx := context.Background()
	stores := memstore.New()
	r := router.New()
	mucSvc := muc.New("example.com", "conference", stores.MUC, nil, nil, r, slog.Default())
	aliceJID, err := stanza.Parse("alice@example.com/phone")
	if err != nil {
		t.Fatalf("parse alice jid: %v", err)
	}
	roomJID, err := stanza.Parse("room@conference.example.com/Alice")
	if err != nil {
		t.Fatalf("parse room jid: %v", err)
	}
	bobJID, err := stanza.Parse("bob@example.com/laptop")
	if err != nil {
		t.Fatalf("parse bob jid: %v", err)
	}

	occupantSession := &routerMockSession{
		j:         aliceJID,
		available: true,
		ch:        make(chan []byte, 8),
	}
	r.Register(occupantSession)

	joinRaw := []byte(`<presence to='room@conference.example.com/Alice' xmlns='jabber:client'><x xmlns='http://jabber.org/protocol/muc'/></presence>`)
	if err := mucSvc.HandleStanza(ctx, joinRaw, "presence", occupantSession.j, roomJID); err != nil {
		t.Fatalf("seed join: %v", err)
	}

	client, server := testPipe(t)
	cfg := makeTestConfig(stores, r, sm.NewStore(64))
	cfg.Modules = &Modules{MUC: mucSvc}
	s := NewSession(&mockTLSConn{server}, cfg)
	s.jid = bobJID

	dec := xml.NewDecoder(strings.NewReader(string(joinRaw)))
	tok, err := dec.Token()
	if err != nil {
		t.Fatalf("token: %v", err)
	}
	start, ok := tok.(xml.StartElement)
	if !ok {
		t.Fatal("expected start element")
	}

	errCh := make(chan error, 1)
	go func() {
		errCh <- handlePresence(ctx, s, start, joinRaw, roomJID)
	}()

	raw := readUntil(t, client, "</presence>", 3*time.Second)
	if err := <-errCh; err != nil {
		t.Fatalf("handlePresence returned error: %v", err)
	}
	if !strings.Contains(raw, `type='error'`) && !strings.Contains(raw, `type="error"`) {
		t.Fatalf("expected presence error stanza, got: %s", raw)
	}
	if !strings.Contains(raw, "conflict") {
		t.Fatalf("expected conflict condition, got: %s", raw)
	}
}
