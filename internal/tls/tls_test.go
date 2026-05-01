package tls

import (
	"bytes"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
)

func genCert(t *testing.T, dir, cn string) (certPEM, keyPEM []byte) {
	t.Helper()
	certFile := filepath.Join(dir, cn+"-cert.pem")
	keyFile := filepath.Join(dir, cn+"-key.pem")
	cmd := exec.Command("openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes",
		"-days", "1",
		"-keyout", keyFile,
		"-out", certFile,
		"-subj", "/CN="+cn,
	)
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("openssl gen cert %s: %v: %s", cn, err, out)
	}
	certPEM, err := os.ReadFile(certFile)
	if err != nil {
		t.Fatalf("read cert %s: %v", cn, err)
	}
	keyPEM, err = os.ReadFile(keyFile)
	if err != nil {
		t.Fatalf("read key %s: %v", cn, err)
	}
	return certPEM, keyPEM
}

var (
	testCertPEM []byte
	testKeyPEM  []byte
)

func TestMain(m *testing.M) {
	dir, err := os.MkdirTemp("", "xmppqr-tls-test")
	if err != nil {
		panic(err)
	}
	defer os.RemoveAll(dir)

	certFile := filepath.Join(dir, "cert.pem")
	keyFile := filepath.Join(dir, "key.pem")

	cmd := exec.Command("openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes",
		"-days", "1",
		"-keyout", keyFile,
		"-out", certFile,
		"-subj", "/CN=localhost",
	)
	if out, err := cmd.CombinedOutput(); err != nil {
		panic("openssl: " + string(out))
	}

	testCertPEM, err = os.ReadFile(certFile)
	if err != nil {
		panic(err)
	}
	testKeyPEM, err = os.ReadFile(keyFile)
	if err != nil {
		panic(err)
	}

	os.Exit(m.Run())
}

func startServer(t *testing.T, opts ServerOptions) (*Listener, []byte) {
	t.Helper()
	srvCtx, err := NewServerContext(testCertPEM, testKeyPEM, opts)
	if err != nil {
		t.Fatalf("NewServerContext: %v", err)
	}
	t.Cleanup(srvCtx.Close)

	ln, err := Listen("tcp", "127.0.0.1:0", srvCtx)
	if err != nil {
		t.Fatalf("Listen: %v", err)
	}
	t.Cleanup(func() { ln.Close() })
	return ln, testCertPEM
}

func TestHandshakeRoundTrip(t *testing.T) {
	ln, caPEM := startServer(t, ServerOptions{})

	errCh := make(chan error, 1)
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			errCh <- err
			return
		}
		defer conn.Close()
		buf := make([]byte, 5)
		n, _ := conn.Read(buf)
		conn.Write(buf[:n])
		errCh <- nil
	}()

	cliCtx, err := NewClientContext(caPEM, ClientOptions{InsecureSkipVerify: true})
	if err != nil {
		t.Fatalf("NewClientContext: %v", err)
	}
	defer cliCtx.Close()

	conn, err := Dial("tcp", ln.Addr().(*net.TCPAddr).String(), cliCtx)
	if err != nil {
		t.Fatalf("Dial: %v", err)
	}
	defer conn.Close()

	msg := []byte("hello")
	if _, err := conn.Write(msg); err != nil {
		t.Fatalf("Write: %v", err)
	}
	got := make([]byte, 5)
	n, err := conn.Read(got)
	if err != nil {
		t.Fatalf("Read: %v", err)
	}
	if !bytes.Equal(msg, got[:n]) {
		t.Fatalf("echo mismatch: got %q want %q", got[:n], msg)
	}
	if err := <-errCh; err != nil {
		t.Fatalf("server: %v", err)
	}
}

func TestPQHybridGroupNegotiated(t *testing.T) {
	ln, caPEM := startServer(t, ServerOptions{
		MinVersion:    0x0304,
		PreferPQHybrid: true,
	})

	type result struct {
		hs  HandshakeState
		err error
	}
	resCh := make(chan result, 1)
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			resCh <- result{err: err}
			return
		}
		defer conn.Close()
		hs := conn.(*Conn).HandshakeState()
		resCh <- result{hs: hs}
	}()

	cliCtx, err := NewClientContext(caPEM, ClientOptions{
		InsecureSkipVerify: true,
		MinVersion:         0x0304,
		PreferPQHybrid:     true,
	})
	if err != nil {
		t.Fatalf("NewClientContext: %v", err)
	}
	defer cliCtx.Close()

	conn, err := Dial("tcp", ln.Addr().(*net.TCPAddr).String(), cliCtx)
	if err != nil {
		t.Fatalf("Dial: %v", err)
	}
	defer conn.Close()

	clientHS := conn.HandshakeState()

	srvRes := <-resCh
	if srvRes.err != nil {
		t.Fatalf("server: %v", srvRes.err)
	}

	if !clientHS.PQHybrid {
		t.Errorf("client: PQHybrid=false, NamedGroup=0x%04x", clientHS.NamedGroup)
	}
	if clientHS.NamedGroup != GroupX25519MLKEM768 {
		t.Errorf("client: NamedGroup=0x%04x, want 0x%04x", clientHS.NamedGroup, GroupX25519MLKEM768)
	}
}

func TestClassicalFallback(t *testing.T) {
	ln, caPEM := startServer(t, ServerOptions{PreferPQHybrid: true})

	errCh := make(chan error, 1)
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			errCh <- err
			return
		}
		conn.Close()
		errCh <- nil
	}()

	cliCtx, err := NewClientContext(caPEM, ClientOptions{
		InsecureSkipVerify: true,
		PreferPQHybrid:     false,
	})
	if err != nil {
		t.Fatalf("NewClientContext: %v", err)
	}
	defer cliCtx.Close()

	conn, err := Dial("tcp", ln.Addr().(*net.TCPAddr).String(), cliCtx)
	if err != nil {
		t.Fatalf("Dial: %v", err)
	}
	defer conn.Close()

	hs := conn.HandshakeState()
	if hs.PQHybrid {
		t.Errorf("expected PQHybrid=false, got true (group=0x%04x)", hs.NamedGroup)
	}

	if err := <-errCh; err != nil {
		t.Fatalf("server: %v", err)
	}
}

func TestExporter(t *testing.T) {
	ln, caPEM := startServer(t, ServerOptions{MinVersion: 0x0304})

	type result struct {
		key []byte
		err error
	}
	resCh := make(chan result, 1)
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			resCh <- result{err: err}
			return
		}
		defer conn.Close()
		key, err := conn.(*Conn).Exporter("EXPORTER-Channel-Binding", nil, 32)
		resCh <- result{key: key, err: err}
	}()

	cliCtx, err := NewClientContext(caPEM, ClientOptions{
		InsecureSkipVerify: true,
		MinVersion:         0x0304,
	})
	if err != nil {
		t.Fatalf("NewClientContext: %v", err)
	}
	defer cliCtx.Close()

	conn, err := Dial("tcp", ln.Addr().(*net.TCPAddr).String(), cliCtx)
	if err != nil {
		t.Fatalf("Dial: %v", err)
	}
	defer conn.Close()

	clientKey, err := conn.Exporter("EXPORTER-Channel-Binding", nil, 32)
	if err != nil {
		t.Skipf("exporter not available: %v", err)
	}

	srvRes := <-resCh
	if srvRes.err != nil {
		t.Skipf("server exporter not available: %v", srvRes.err)
	}

	if !bytes.Equal(clientKey, srvRes.key) {
		t.Errorf("exporter mismatch:\nclient: %x\nserver: %x", clientKey, srvRes.key)
	}
}

func TestMTLSHandshake(t *testing.T) {
	dir := t.TempDir()

	srvCert, srvKey := genCert(t, dir, "server")
	cliCert, cliKey := genCert(t, dir, "client")

	srvCtx, err := NewServerContext(srvCert, srvKey, ServerOptions{
		ClientAuth: true,
		ClientCAs:  cliCert,
	})
	if err != nil {
		t.Fatalf("server context: %v", err)
	}
	defer srvCtx.Close()

	ln, err := Listen("tcp", "127.0.0.1:0", srvCtx)
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close()

	type srvResult struct {
		hs  HandshakeState
		err error
	}
	resCh := make(chan srvResult, 1)
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			resCh <- srvResult{err: err}
			return
		}
		defer conn.Close()
		hs := conn.(*Conn).HandshakeState()
		resCh <- srvResult{hs: hs}
	}()

	cliCtx, err := NewClientContext(srvCert, ClientOptions{
		CertPEM: cliCert,
		KeyPEM:  cliKey,
	})
	if err != nil {
		t.Fatalf("client context: %v", err)
	}
	defer cliCtx.Close()

	conn, err := Dial("tcp", ln.Addr().(*net.TCPAddr).String(), cliCtx)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn.Close()

	clientHS := conn.HandshakeState()

	res := <-resCh
	if res.err != nil {
		t.Fatalf("server accept: %v", res.err)
	}

	if len(res.hs.PeerCertChain) == 0 {
		t.Fatal("server: expected peer cert chain, got none")
	}
	if len(clientHS.PeerCertChain) == 0 {
		t.Fatal("client: expected peer cert chain, got none")
	}
}
