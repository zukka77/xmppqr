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

type ServerOptions struct {
	MinVersion    uint16
	PreferPQHybrid bool
	ClientAuth    bool
	ClientCAs     []byte
}

type ClientOptions struct {
	MinVersion         uint16
	PreferPQHybrid     bool
	ServerName         string
	InsecureSkipVerify bool
	CertPEM            []byte
	KeyPEM             []byte
}

type Context struct {
	ctx    *C.WOLFSSL_CTX
	isServer bool
}

func applyGroups(ctx *C.WOLFSSL_CTX, preferPQ bool) error {
	prefs := defaultGroupPreference(preferPQ)
	cGroups := make([]C.int, len(prefs))
	for i, g := range prefs {
		cGroups[i] = C.int(g)
	}
	rc := C.wolfSSL_CTX_set_groups(ctx, &cGroups[0], C.int(len(cGroups)))
	if rc != C.WOLFSSL_SUCCESS {
		return wolfCtxErr(rc)
	}
	return nil
}

func applyMinVersion(ctx *C.WOLFSSL_CTX, minVer uint16) error {
	if minVer == 0 {
		return nil
	}
	rc := C.wolfSSL_CTX_set_min_proto_version(ctx, C.int(minVer))
	if rc != C.WOLFSSL_SUCCESS {
		return wolfCtxErr(rc)
	}
	return nil
}

func NewServerContext(certPEM, keyPEM []byte, opts ServerOptions) (*Context, error) {
	method := C.wolfSSLv23_server_method()
	if method == nil {
		return nil, fmt.Errorf("wolfssl: failed to create server method")
	}
	cctx := C.wolfSSL_CTX_new(method)
	if cctx == nil {
		return nil, fmt.Errorf("wolfssl: failed to create server context")
	}

	if err := applyMinVersion(cctx, opts.MinVersion); err != nil {
		C.wolfSSL_CTX_free(cctx)
		return nil, err
	}

	if err := applyGroups(cctx, opts.PreferPQHybrid); err != nil {
		C.wolfSSL_CTX_free(cctx)
		return nil, err
	}

	certPtr := (*C.uchar)(unsafe.Pointer(&certPEM[0]))
	rc := C.wolfSSL_CTX_use_certificate_chain_buffer(cctx, certPtr, C.long(len(certPEM)))
	if rc != C.WOLFSSL_SUCCESS {
		C.wolfSSL_CTX_free(cctx)
		return nil, wolfCtxErr(rc)
	}

	keyPtr := (*C.uchar)(unsafe.Pointer(&keyPEM[0]))
	rc = C.wolfSSL_CTX_use_PrivateKey_buffer(cctx, keyPtr, C.long(len(keyPEM)), C.WOLFSSL_FILETYPE_PEM)
	if rc != C.WOLFSSL_SUCCESS {
		C.wolfSSL_CTX_free(cctx)
		return nil, wolfCtxErr(rc)
	}

	if opts.ClientAuth {
		mode := C.WOLFSSL_VERIFY_PEER | C.WOLFSSL_VERIFY_FAIL_IF_NO_PEER_CERT
		C.wolfSSL_CTX_set_verify(cctx, C.int(mode), nil)
		if len(opts.ClientCAs) > 0 {
			caPtr := (*C.uchar)(unsafe.Pointer(&opts.ClientCAs[0]))
			rc = C.wolfSSL_CTX_load_verify_buffer(cctx, caPtr, C.long(len(opts.ClientCAs)), C.WOLFSSL_FILETYPE_PEM)
			if rc != C.WOLFSSL_SUCCESS {
				C.wolfSSL_CTX_free(cctx)
				return nil, wolfCtxErr(rc)
			}
		}
	} else {
		C.wolfSSL_CTX_set_verify(cctx, C.WOLFSSL_VERIFY_NONE, nil)
	}

	return &Context{ctx: cctx, isServer: true}, nil
}

func NewClientContext(rootCAs []byte, opts ClientOptions) (*Context, error) {
	method := C.wolfSSLv23_client_method()
	if method == nil {
		return nil, fmt.Errorf("wolfssl: failed to create client method")
	}
	cctx := C.wolfSSL_CTX_new(method)
	if cctx == nil {
		return nil, fmt.Errorf("wolfssl: failed to create client context")
	}

	if err := applyMinVersion(cctx, opts.MinVersion); err != nil {
		C.wolfSSL_CTX_free(cctx)
		return nil, err
	}

	if err := applyGroups(cctx, opts.PreferPQHybrid); err != nil {
		C.wolfSSL_CTX_free(cctx)
		return nil, err
	}

	if opts.InsecureSkipVerify {
		C.wolfSSL_CTX_set_verify(cctx, C.WOLFSSL_VERIFY_NONE, nil)
	} else {
		if len(rootCAs) > 0 {
			caPtr := (*C.uchar)(unsafe.Pointer(&rootCAs[0]))
			rc := C.wolfSSL_CTX_load_verify_buffer(cctx, caPtr, C.long(len(rootCAs)), C.WOLFSSL_FILETYPE_PEM)
			if rc != C.WOLFSSL_SUCCESS {
				C.wolfSSL_CTX_free(cctx)
				return nil, wolfCtxErr(rc)
			}
		}
	}

	if len(opts.CertPEM) > 0 {
		certPtr := (*C.uchar)(unsafe.Pointer(&opts.CertPEM[0]))
		rc := C.wolfSSL_CTX_use_certificate_chain_buffer(cctx, certPtr, C.long(len(opts.CertPEM)))
		if rc != C.WOLFSSL_SUCCESS {
			C.wolfSSL_CTX_free(cctx)
			return nil, wolfCtxErr(rc)
		}
		keyPtr := (*C.uchar)(unsafe.Pointer(&opts.KeyPEM[0]))
		rc = C.wolfSSL_CTX_use_PrivateKey_buffer(cctx, keyPtr, C.long(len(opts.KeyPEM)), C.WOLFSSL_FILETYPE_PEM)
		if rc != C.WOLFSSL_SUCCESS {
			C.wolfSSL_CTX_free(cctx)
			return nil, wolfCtxErr(rc)
		}
	}

	return &Context{ctx: cctx, isServer: false}, nil
}

func (c *Context) Close() {
	if c.ctx != nil {
		C.wolfSSL_CTX_free(c.ctx)
		c.ctx = nil
	}
}
