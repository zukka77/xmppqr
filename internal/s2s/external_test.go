package s2s

import (
	"context"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	"github.com/danielinux/xmppqr/internal/stanza"
	xtls "github.com/danielinux/xmppqr/internal/tls"
)

func genMTLSCert(t *testing.T, dir, domain string) (certPEM, keyPEM []byte) {
	t.Helper()
	certFile := filepath.Join(dir, domain+"-cert.pem")
	keyFile := filepath.Join(dir, domain+"-key.pem")
	cmd := exec.Command("openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes",
		"-days", "1",
		"-keyout", keyFile,
		"-out", certFile,
		"-subj", "/CN="+domain,
		"-addext", "subjectAltName=otherName:1.3.6.1.5.5.7.8.5;UTF8:"+domain,
	)
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("openssl %s: %v: %s", domain, err, out)
	}
	var err error
	certPEM, err = os.ReadFile(certFile)
	if err != nil {
		t.Fatalf("read cert %s: %v", domain, err)
	}
	keyPEM, err = os.ReadFile(keyFile)
	if err != nil {
		t.Fatalf("read key %s: %v", domain, err)
	}
	return
}

func genMTLSCertWrongDomain(t *testing.T, dir, cn, sanDomain string) (certPEM, keyPEM []byte) {
	t.Helper()
	certFile := filepath.Join(dir, cn+"-cert.pem")
	keyFile := filepath.Join(dir, cn+"-key.pem")
	cmd := exec.Command("openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes",
		"-days", "1",
		"-keyout", keyFile,
		"-out", certFile,
		"-subj", "/CN="+cn,
		"-addext", "subjectAltName=otherName:1.3.6.1.5.5.7.8.5;UTF8:"+sanDomain,
	)
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("openssl %s: %v: %s", cn, err, out)
	}
	var err error
	certPEM, err = os.ReadFile(certFile)
	if err != nil {
		t.Fatalf("read cert %s: %v", cn, err)
	}
	keyPEM, err = os.ReadFile(keyFile)
	if err != nil {
		t.Fatalf("read key %s: %v", cn, err)
	}
	return
}

func newMTLSPool(t *testing.T, domain string, secret []byte, inbound InboundRouter, certPEM, keyPEM, caCert []byte) (*Pool, *xtls.Context) {
	t.Helper()

	srvCtx, err := xtls.NewServerContext(certPEM, keyPEM, xtls.ServerOptions{
		ClientAuth: true,
		ClientCAs:  caCert,
	})
	if err != nil {
		t.Fatalf("server ctx %s: %v", domain, err)
	}
	t.Cleanup(srvCtx.Close)

	cliCtx, err := xtls.NewClientContext(caCert, xtls.ClientOptions{
		CertPEM:            certPEM,
		KeyPEM:             keyPEM,
		InsecureSkipVerify: true,
	})
	if err != nil {
		t.Fatalf("client ctx %s: %v", domain, err)
	}
	t.Cleanup(cliCtx.Close)

	p := New(domain, secret, cliCtx, inbound, nil)
	p.SetMTLS(true)
	p.dialer = &plainDialer{}
	return p, srvCtx
}

func TestSASLExternalSuccess(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	dir := t.TempDir()
	secret := []byte("external-test-secret")

	alphaCert, alphaKey := genMTLSCert(t, dir, "alpha.test")
	betaCert, betaKey := genMTLSCert(t, dir, "beta.test")

	combinedCA := append(alphaCert, betaCert...)

	alphaInbound := newMockInbound()
	betaInbound := newMockInbound()

	alphaPool, _ := newMTLSPool(t, "alpha.test", secret, alphaInbound, alphaCert, alphaKey, combinedCA)
	betaPool, betaSrvCtx := newMTLSPool(t, "beta.test", secret, betaInbound, betaCert, betaKey, combinedCA)

	tcpLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer tcpLn.Close()

	betaAddr := tcpLn.Addr().String()
	alphaPool.PinTarget("beta.test", betaAddr)

	go func() {
		for {
			raw, err := tcpLn.Accept()
			if err != nil {
				return
			}
			tcp, ok := raw.(*net.TCPConn)
			if !ok {
				raw.Close()
				continue
			}
			go func() {
				if err := betaPool.AcceptInbound(ctx, tcp, betaSrvCtx); err != nil {
					_ = err
				}
			}()
		}
	}()

	conn, err := alphaPool.connectOutbound(ctx, "beta.test")
	if err != nil {
		t.Fatalf("connectOutbound: %v", err)
	}

	stanza := []byte(fmt.Sprintf("<message from='user@alpha.test' to='user@beta.test'><body>mtls</body></message>"))
	if err := conn.WriteStanza(stanza); err != nil {
		t.Fatalf("write stanza: %v", err)
	}

	if !betaInbound.waitFor(1, 5*time.Second) {
		t.Fatal("stanza did not arrive at beta via SASL EXTERNAL")
	}

	alphaPool.mu.RLock()
	_, dialbackUsed := alphaPool.streamIDs["beta.test"]
	alphaPool.mu.RUnlock()
	if dialbackUsed {
		t.Fatal("expected EXTERNAL path (no streamID entry), but streamIDs was populated — dialback was used")
	}
}

func TestSASLExternalSANMismatch(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	dir := t.TempDir()
	secret := []byte("external-test-secret")

	wrongCert, wrongKey := genMTLSCertWrongDomain(t, dir, "alpha-wrong", "wrong.domain")
	betaCert, betaKey := genMTLSCert(t, dir, "beta.test")

	combinedCA := append(wrongCert, betaCert...)

	alphaInbound := newMockInbound()
	betaInbound := newMockInbound()

	alphaPool, _ := newMTLSPool(t, "alpha.test", secret, alphaInbound, wrongCert, wrongKey, combinedCA)
	betaPool, betaSrvCtx := newMTLSPool(t, "beta.test", secret, betaInbound, betaCert, betaKey, combinedCA)

	tcpLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer tcpLn.Close()

	alphaPool.PinTarget("beta.test", tcpLn.Addr().String())

	go func() {
		for {
			raw, err := tcpLn.Accept()
			if err != nil {
				return
			}
			tcp, ok := raw.(*net.TCPConn)
			if !ok {
				raw.Close()
				continue
			}
			go func() {
				if err := betaPool.AcceptInbound(ctx, tcp, betaSrvCtx); err != nil {
					_ = err
				}
			}()
		}
	}()

	_, err = alphaPool.connectOutbound(ctx, "beta.test")
	if err == nil {
		t.Fatal("expected connectOutbound to fail due to SAN mismatch, but it succeeded")
	}
}

func TestExternalNotOfferedFallsBackToDialback(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	secret := []byte("shared-secret-fallback")
	alphaInbound := newMockInbound()
	betaInbound := newMockInbound()

	pd := newPipeDialer()
	alpha := newTestPool("alpha.test", secret, alphaInbound, pd)
	beta := newTestPool("beta.test", secret, betaInbound, nil)
	alpha.SetMTLS(true)

	go func() {
		conn := <-pd.serverChan("beta.test")
		if err := beta.AcceptInbound(ctx, conn, nil); err != nil {
			_ = err
		}
	}()

	stanzaBytes := []byte("<message from='user@alpha.test' to='user@beta.test'><body>fallback</body></message>")
	alphaJID := stanza.JID{Local: "user", Domain: "alpha.test"}
	betaJID := stanza.JID{Local: "user", Domain: "beta.test"}
	if err := alpha.Send(ctx, alphaJID, betaJID, stanzaBytes); err != nil {
		t.Fatalf("Send: %v", err)
	}

	if !betaInbound.waitFor(1, 5*time.Second) {
		t.Fatal("fallback dialback stanza did not arrive")
	}
}
