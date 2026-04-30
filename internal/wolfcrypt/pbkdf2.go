package wolfcrypt

/*
#cgo pkg-config: wolfssl
#include <wolfssl/options.h>
#include <wolfssl/wolfcrypt/pwdbased.h>
#include <wolfssl/wolfcrypt/hmac.h>
*/
import "C"
import (
	"errors"
	"unsafe"
)

const (
	HashSHA256 = int(C.WC_SHA256)
	HashSHA512 = int(C.WC_SHA512)
)

func PBKDF2(password, salt []byte, iter, keyLen, hash int) ([]byte, error) {
	if iter <= 0 || keyLen <= 0 {
		return nil, errors.New("pbkdf2: invalid parameters")
	}
	out := make([]byte, keyLen)
	var passp, saltp *C.byte
	if len(password) > 0 {
		passp = (*C.byte)(unsafe.Pointer(&password[0]))
	}
	if len(salt) > 0 {
		saltp = (*C.byte)(unsafe.Pointer(&salt[0]))
	}
	rc := C.wc_PBKDF2(
		(*C.byte)(unsafe.Pointer(&out[0])),
		passp, C.int(len(password)),
		saltp, C.int(len(salt)),
		C.int(iter), C.int(keyLen), C.int(hash),
	)
	if rc != 0 {
		return nil, wolfErr(rc)
	}
	return out, nil
}
