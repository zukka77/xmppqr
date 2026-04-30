package wolfcrypt

/*
#cgo pkg-config: wolfssl
#include <wolfssl/options.h>
#include <wolfssl/wolfcrypt/sha.h>
#include <stdlib.h>
*/
import "C"
import "unsafe"

func SHA1(data []byte) [20]byte {
	h := (*C.wc_Sha)(C.calloc(1, C.sizeof_wc_Sha))
	defer C.free(unsafe.Pointer(h))
	var out [20]byte
	C.wc_InitSha(h)
	if len(data) > 0 {
		C.wc_ShaUpdate(h, (*C.byte)(unsafe.Pointer(&data[0])), C.word32(len(data)))
	}
	C.wc_ShaFinal(h, (*C.byte)(unsafe.Pointer(&out[0])))
	C.wc_ShaFree(h)
	return out
}
