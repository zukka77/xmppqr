package tls

/*
#cgo pkg-config: wolfssl
#include <wolfssl/options.h>
#include <wolfssl/ssl.h>
#include <stdlib.h>
*/
import "C"
import (
	"net"
	"time"
	"unsafe"
)

type Conn struct {
	ssl    *C.WOLFSSL
	tcp    *net.TCPConn
	handle *connHandle
}

func newConn(ssl *C.WOLFSSL, tcp *net.TCPConn, h *connHandle) *Conn {
	return &Conn{ssl: ssl, tcp: tcp, handle: h}
}

func (c *Conn) Read(p []byte) (int, error) {
	if len(p) == 0 {
		return 0, nil
	}
	n := C.wolfSSL_read(c.ssl, unsafe.Pointer(&p[0]), C.int(len(p)))
	if n > 0 {
		return int(n), nil
	}
	err := C.wolfSSL_get_error(c.ssl, n)
	if err == C.WOLFSSL_ERROR_WANT_READ || err == C.WOLFSSL_ERROR_WANT_WRITE {
		return 0, nil
	}
	return 0, wolfErr(c.ssl, n)
}

func (c *Conn) Write(p []byte) (int, error) {
	if len(p) == 0 {
		return 0, nil
	}
	n := C.wolfSSL_write(c.ssl, unsafe.Pointer(&p[0]), C.int(len(p)))
	if n > 0 {
		return int(n), nil
	}
	err := C.wolfSSL_get_error(c.ssl, n)
	if err == C.WOLFSSL_ERROR_WANT_READ || err == C.WOLFSSL_ERROR_WANT_WRITE {
		return 0, nil
	}
	return 0, wolfErr(c.ssl, n)
}

func (c *Conn) Close() error {
	if c.ssl != nil {
		C.wolfSSL_shutdown(c.ssl)
		C.wolfSSL_free(c.ssl)
		c.ssl = nil
		if c.handle != nil {
			c.handle.free()
			c.handle = nil
		}
	}
	return c.tcp.Close()
}

func (c *Conn) LocalAddr() net.Addr  { return c.tcp.LocalAddr() }
func (c *Conn) RemoteAddr() net.Addr { return c.tcp.RemoteAddr() }

func (c *Conn) SetDeadline(t time.Time) error      { return c.tcp.SetDeadline(t) }
func (c *Conn) SetReadDeadline(t time.Time) error  { return c.tcp.SetReadDeadline(t) }
func (c *Conn) SetWriteDeadline(t time.Time) error { return c.tcp.SetWriteDeadline(t) }
