// SPDX-License-Identifier: AGPL-3.0-or-later
package wolfcrypt

/*
#cgo pkg-config: wolfssl
#include <wolfssl/options.h>
#include <wolfssl/wolfcrypt/blake2.h>
#include <stdlib.h>
*/
import "C"
import "unsafe"

// Blake2b160 returns a 20-byte (160-bit) BLAKE2b digest of data.
func Blake2b160(data []byte) ([20]byte, error) {
	b := (*C.Blake2b)(C.calloc(1, C.sizeof_Blake2b))
	if b == nil {
		return [20]byte{}, wolfErr(-1)
	}
	defer C.free(unsafe.Pointer(b))
	if rc := C.wc_InitBlake2b(b, 20); rc != 0 {
		return [20]byte{}, wolfErr(rc)
	}
	if len(data) > 0 {
		if rc := C.wc_Blake2bUpdate(b, (*C.byte)(unsafe.Pointer(&data[0])), C.word32(len(data))); rc != 0 {
			return [20]byte{}, wolfErr(rc)
		}
	}
	var out [20]byte
	if rc := C.wc_Blake2bFinal(b, (*C.byte)(unsafe.Pointer(&out[0])), 20); rc != 0 {
		return [20]byte{}, wolfErr(rc)
	}
	return out, nil
}
