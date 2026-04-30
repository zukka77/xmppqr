package tls

/*
#cgo pkg-config: wolfssl
#include <wolfssl/options.h>
#include <wolfssl/ssl.h>
#include <stdlib.h>
*/
import "C"
import "unsafe"

type HandshakeState struct {
	Version      uint16
	CipherSuite  uint16
	NamedGroup   uint16
	PQHybrid     bool
	PeerCertChain [][]byte
	SNI          string
}

func versionStringToCode(s string) uint16 {
	switch s {
	case "TLSv1.2":
		return 0x0303
	case "TLSv1.3":
		return 0x0304
	default:
		return 0
	}
}

func (c *Conn) HandshakeState() HandshakeState {
	var hs HandshakeState

	ver := C.wolfSSL_get_version(c.ssl)
	if ver != nil {
		hs.Version = versionStringToCode(C.GoString(ver))
	}

	cipher := C.wolfSSL_get_current_cipher(c.ssl)
	if cipher != nil {
		id := C.wolfSSL_CIPHER_get_id(cipher)
		hs.CipherSuite = uint16(id & 0xFFFF)
	}

	curveName := C.wolfSSL_get_curve_name(c.ssl)
	if curveName != nil {
		name := C.GoString(curveName)
		hs.NamedGroup = curveNameToIANA(name)
	}

	hs.PQHybrid = (hs.NamedGroup == GroupX25519MLKEM768)

	chain := C.wolfSSL_get_peer_chain(c.ssl)
	if chain != nil {
		count := int(C.wolfSSL_get_chain_count(chain))
		for i := 0; i < count; i++ {
			der := C.wolfSSL_get_chain_cert(chain, C.int(i))
			length := int(C.wolfSSL_get_chain_length(chain, C.int(i)))
			if der != nil && length > 0 {
				cert := C.GoBytes(unsafe.Pointer(der), C.int(length))
				hs.PeerCertChain = append(hs.PeerCertChain, cert)
			}
		}
	}

	sni := C.wolfSSL_get_servername(c.ssl, C.uchar(C.WOLFSSL_SNI_HOST_NAME))
	if sni != nil {
		hs.SNI = C.GoString(sni)
	}

	return hs
}

func curveNameToIANA(name string) uint16 {
	switch name {
	case "X25519":
		return GroupX25519
	case "SECP256R1", "P-256":
		return GroupSecp256r1
	case "SECP384R1", "P-384":
		return GroupSecp384r1
	case "X25519MLKEM768", "P256_ML_KEM_768", "X25519_ML_KEM_768":
		return GroupX25519MLKEM768
	default:
		return 0
	}
}
