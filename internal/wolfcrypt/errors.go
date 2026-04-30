package wolfcrypt

/*
#cgo pkg-config: wolfssl
#include <wolfssl/options.h>
#include <wolfssl/wolfcrypt/error-crypt.h>
*/
import "C"
import "fmt"

func wolfErr(rc C.int) error {
	if rc == 0 {
		return nil
	}
	return fmt.Errorf("wolfcrypt error: %d", int(rc))
}
