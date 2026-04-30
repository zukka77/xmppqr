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
	"unsafe"
)

func Dial(network, addr string, ctx *Context) (*Conn, error) {
	tc, err := net.Dial(network, addr)
	if err != nil {
		return nil, err
	}
	tcp, ok := tc.(*net.TCPConn)
	if !ok {
		tc.Close()
		return nil, fmt.Errorf("wolfssl: expected *net.TCPConn")
	}

	ssl := C.wolfSSL_new(ctx.ctx)
	if ssl == nil {
		tcp.Close()
		return nil, fmt.Errorf("wolfssl: failed to create SSL object")
	}

	host, _, _ := net.SplitHostPort(addr)
	if host != "" {
		cs := C.CString(host)
		C.wolfSSL_UseSNI(ssl, C.uchar(C.WOLFSSL_SNI_HOST_NAME), unsafe.Pointer(cs), C.word16(len(host)))
		C.free(unsafe.Pointer(cs))
	}

	h := registerConn(tcp)
	setupSSLIO(ssl, h)

	rc := C.wolfSSL_connect(ssl)
	if rc != C.WOLFSSL_SUCCESS {
		err := wolfErr(ssl, rc)
		h.free()
		C.wolfSSL_free(ssl)
		tcp.Close()
		return nil, err
	}

	return newConn(ssl, tcp, h), nil
}
