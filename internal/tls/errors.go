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
	"unsafe"
)

func wolfErr(ssl *C.WOLFSSL, rc C.int) error {
	if rc == C.WOLFSSL_SUCCESS {
		return nil
	}
	var code C.int
	if ssl != nil {
		code = C.wolfSSL_get_error(ssl, rc)
	} else {
		code = rc
	}
	buf := (*C.char)(C.calloc(1, 80))
	defer C.free(unsafe.Pointer(buf))
	C.wolfSSL_ERR_error_string(C.ulong(code), buf)
	return fmt.Errorf("wolfssl: %s (code %d)", C.GoString(buf), int(code))
}

func wolfCtxErr(rc C.int) error {
	if rc == C.WOLFSSL_SUCCESS {
		return nil
	}
	buf := (*C.char)(C.calloc(1, 80))
	defer C.free(unsafe.Pointer(buf))
	C.wolfSSL_ERR_error_string(C.ulong(rc), buf)
	return fmt.Errorf("wolfssl: %s (code %d)", C.GoString(buf), int(rc))
}
