package wolfcrypt

/*
#cgo pkg-config: wolfssl
#include <wolfssl/options.h>
#include <wolfssl/wolfcrypt/pwdbased.h>
*/
import "C"
import (
	"errors"
	"math/bits"
	"unsafe"
)

func Scrypt(password, salt []byte, n, r, p, keyLen int) ([]byte, error) {
	if n < 2 || bits.OnesCount(uint(n)) != 1 {
		return nil, errors.New("scrypt: N must be a power of 2 greater than 1")
	}
	if r <= 0 || p <= 0 || keyLen <= 0 {
		return nil, errors.New("scrypt: invalid parameters")
	}
	log2n := bits.Len(uint(n)) - 1

	out := make([]byte, keyLen)
	var passp, saltp *C.byte
	if len(password) > 0 {
		passp = (*C.byte)(unsafe.Pointer(&password[0]))
	}
	if len(salt) > 0 {
		saltp = (*C.byte)(unsafe.Pointer(&salt[0]))
	}
	rc := C.wc_scrypt(
		(*C.byte)(unsafe.Pointer(&out[0])),
		passp, C.int(len(password)),
		saltp, C.int(len(salt)),
		C.int(log2n), C.int(r), C.int(p), C.int(keyLen),
	)
	if rc != 0 {
		return nil, wolfErr(rc)
	}
	return out, nil
}
