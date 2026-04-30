package tls

/*
#cgo pkg-config: wolfssl
#include <wolfssl/options.h>
#include <wolfssl/ssl.h>
#include <stdlib.h>
*/
import "C"
import (
	"errors"
	"unsafe"
)

func (c *Conn) Exporter(label string, context []byte, n int) ([]byte, error) {
	out := make([]byte, n)
	cLabel := C.CString(label)
	defer C.free(unsafe.Pointer(cLabel))

	var ctxPtr *C.uchar
	var ctxLen C.size_t
	useCtx := C.int(0)
	if context != nil {
		ctxPtr = (*C.uchar)(unsafe.Pointer(&context[0]))
		ctxLen = C.size_t(len(context))
		useCtx = 1
	}

	rc := C.wolfSSL_export_keying_material(
		c.ssl,
		(*C.uchar)(unsafe.Pointer(&out[0])),
		C.size_t(n),
		cLabel,
		C.size_t(len(label)),
		ctxPtr,
		ctxLen,
		useCtx,
	)
	if rc != C.WOLFSSL_SUCCESS {
		return nil, errors.New("wolfssl: export_keying_material failed")
	}
	return out, nil
}
