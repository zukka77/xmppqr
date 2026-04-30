package wolfcrypt

/*
#cgo pkg-config: wolfssl
#include <wolfssl/options.h>
#include <wolfssl/wolfcrypt/random.h>
#include <stdlib.h>
*/
import "C"
import (
	"sync"
	"unsafe"
)

var (
	rng     *C.WC_RNG
	rngMu   sync.Mutex
	rngInit bool
)

func getRNG() (*C.WC_RNG, error) {
	if !rngInit {
		rng = (*C.WC_RNG)(C.calloc(1, C.sizeof_WC_RNG))
		if rng == nil {
			return nil, wolfErr(-1)
		}
		if rc := C.wc_InitRng(rng); rc != 0 {
			C.free(unsafe.Pointer(rng))
			rng = nil
			return nil, wolfErr(rc)
		}
		rngInit = true
	}
	return rng, nil
}

func Read(b []byte) (int, error) {
	if len(b) == 0 {
		return 0, nil
	}
	rngMu.Lock()
	defer rngMu.Unlock()
	r, err := getRNG()
	if err != nil {
		return 0, err
	}
	rc := C.wc_RNG_GenerateBlock(r, (*C.byte)(unsafe.Pointer(&b[0])), C.word32(len(b)))
	if rc != 0 {
		return 0, wolfErr(rc)
	}
	return len(b), nil
}
