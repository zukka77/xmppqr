package tls

/*
#cgo pkg-config: wolfssl
#include <wolfssl/options.h>
#include <wolfssl/ssl.h>
#include <wolfssl/wolfio.h>
#include <stdlib.h>
#include <string.h>

extern int goWolfSSLRecv(WOLFSSL *ssl, char *buf, int sz, void *ctx);
extern int goWolfSSLSend(WOLFSSL *ssl, char *buf, int sz, void *ctx);

static void setupIOCallbacks(WOLFSSL *ssl, void *ctx) {
    wolfSSL_SSLSetIORecv(ssl, goWolfSSLRecv);
    wolfSSL_SSLSetIOSend(ssl, goWolfSSLSend);
    wolfSSL_SetIOReadCtx(ssl, ctx);
    wolfSSL_SetIOWriteCtx(ssl, ctx);
}
*/
import "C"
import (
	"io"
	"net"
	"sync"
	"unsafe"
)

var (
	connMu    sync.RWMutex
	connTable = map[uint64]net.Conn{}
	connNext  uint64 = 1
)

// connHandle is a C-allocated uint64 whose address we pass as the wolfSSL IO
// context. We can't pass the bare integer cast as unsafe.Pointer — checkptr
// rejects fabricated pointers — so we allocate one C uint64 per connection,
// hand wolfSSL its address, and free on unregister.
type connHandle struct {
	id  uint64
	ptr unsafe.Pointer
}

func registerConn(c net.Conn) *connHandle {
	connMu.Lock()
	id := connNext
	connNext++
	connTable[id] = c
	connMu.Unlock()
	p := C.calloc(1, C.size_t(unsafe.Sizeof(C.uint64_t(0))))
	*(*uint64)(p) = id
	return &connHandle{id: id, ptr: p}
}

func (h *connHandle) free() {
	connMu.Lock()
	delete(connTable, h.id)
	connMu.Unlock()
	if h.ptr != nil {
		C.free(h.ptr)
		h.ptr = nil
	}
}

func lookupConn(id uint64) net.Conn {
	connMu.RLock()
	c := connTable[id]
	connMu.RUnlock()
	return c
}

//export goWolfSSLRecv
func goWolfSSLRecv(ssl *C.WOLFSSL, buf *C.char, sz C.int, ctx unsafe.Pointer) C.int {
	id := *(*uint64)(ctx)
	c := lookupConn(id)
	if c == nil {
		return -1
	}
	b := make([]byte, int(sz))
	n, err := c.Read(b)
	if n > 0 {
		C.memcpy(unsafe.Pointer(buf), unsafe.Pointer(&b[0]), C.size_t(n))
		return C.int(n)
	}
	if err == io.EOF {
		return 0
	}
	if err != nil {
		return -1
	}
	return C.WOLFSSL_CBIO_ERR_WANT_READ
}

//export goWolfSSLSend
func goWolfSSLSend(ssl *C.WOLFSSL, buf *C.char, sz C.int, ctx unsafe.Pointer) C.int {
	id := *(*uint64)(ctx)
	c := lookupConn(id)
	if c == nil {
		return -1
	}
	b := C.GoBytes(unsafe.Pointer(buf), sz)
	n, err := c.Write(b)
	if n > 0 {
		return C.int(n)
	}
	if err != nil {
		return -1
	}
	return C.WOLFSSL_CBIO_ERR_WANT_WRITE
}

func setupSSLIO(ssl *C.WOLFSSL, h *connHandle) {
	C.setupIOCallbacks(ssl, h.ptr)
}
