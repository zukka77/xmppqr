package tls

/*
#cgo pkg-config: wolfssl
#include <wolfssl/options.h>
#include <wolfssl/ssl.h>
#include <stdlib.h>
*/
import "C"
import (
	"fmt"
	"net"
)

type Listener struct {
	inner net.Listener
	ctx   *Context
}

func Listen(network, addr string, ctx *Context) (*Listener, error) {
	l, err := net.Listen(network, addr)
	if err != nil {
		return nil, err
	}
	return &Listener{inner: l, ctx: ctx}, nil
}

func (l *Listener) Accept() (net.Conn, error) {
	tc, err := l.inner.Accept()
	if err != nil {
		return nil, err
	}
	tcp, ok := tc.(*net.TCPConn)
	if !ok {
		tc.Close()
		return nil, fmt.Errorf("wolfssl: expected *net.TCPConn")
	}

	ssl := C.wolfSSL_new(l.ctx.ctx)
	if ssl == nil {
		tcp.Close()
		return nil, fmt.Errorf("wolfssl: failed to create SSL object")
	}

	h := registerConn(tcp)
	setupSSLIO(ssl, h)

	rc := C.wolfSSL_accept(ssl)
	if rc != C.WOLFSSL_SUCCESS {
		err := wolfErr(ssl, rc)
		h.free()
		C.wolfSSL_free(ssl)
		tcp.Close()
		return nil, err
	}

	return newConn(ssl, tcp, h), nil
}

func (l *Listener) Addr() net.Addr { return l.inner.Addr() }

func (l *Listener) Close() error { return l.inner.Close() }

// ServerHandshake performs a wolfSSL accept on an already-established TCP
// connection. Used by STARTTLS upgrade flow (XEP-0220 / RFC 6120 §5).
func ServerHandshake(ctx *Context, tcp *net.TCPConn) (*Conn, error) {
	ssl := C.wolfSSL_new(ctx.ctx)
	if ssl == nil {
		return nil, fmt.Errorf("wolfssl: failed to create SSL object")
	}
	h := registerConn(tcp)
	setupSSLIO(ssl, h)
	rc := C.wolfSSL_accept(ssl)
	if rc != C.WOLFSSL_SUCCESS {
		err := wolfErr(ssl, rc)
		h.free()
		C.wolfSSL_free(ssl)
		return nil, err
	}
	return newConn(ssl, tcp, h), nil
}
