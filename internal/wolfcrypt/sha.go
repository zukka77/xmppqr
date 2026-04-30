package wolfcrypt

/*
#cgo pkg-config: wolfssl
#include <wolfssl/options.h>
#include <wolfssl/wolfcrypt/sha256.h>
#include <wolfssl/wolfcrypt/sha512.h>
#include <stdlib.h>
*/
import "C"
import "unsafe"

func SHA256(data []byte) [32]byte {
	h := (*C.wc_Sha256)(C.calloc(1, C.sizeof_wc_Sha256))
	defer C.free(unsafe.Pointer(h))
	var out [32]byte
	C.wc_InitSha256(h)
	if len(data) > 0 {
		C.wc_Sha256Update(h, (*C.byte)(unsafe.Pointer(&data[0])), C.word32(len(data)))
	}
	C.wc_Sha256Final(h, (*C.byte)(unsafe.Pointer(&out[0])))
	C.wc_Sha256Free(h)
	return out
}

func SHA512(data []byte) [64]byte {
	h := (*C.wc_Sha512)(C.calloc(1, C.sizeof_wc_Sha512))
	defer C.free(unsafe.Pointer(h))
	var out [64]byte
	C.wc_InitSha512(h)
	if len(data) > 0 {
		C.wc_Sha512Update(h, (*C.byte)(unsafe.Pointer(&data[0])), C.word32(len(data)))
	}
	C.wc_Sha512Final(h, (*C.byte)(unsafe.Pointer(&out[0])))
	C.wc_Sha512Free(h)
	return out
}
