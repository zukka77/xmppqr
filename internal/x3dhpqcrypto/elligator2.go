// SPDX-License-Identifier: AGPL-3.0-or-later
package x3dhpqcrypto

import (
	"encoding/binary"
	"math/big"

	"github.com/danielinux/xmppqr/internal/wolfcrypt"
)

// Non-constant-time field arithmetic is acceptable here: the input to H2C is
// already hashed from all public transcript context, so timing observations
// reveal nothing beyond what a passive network observer sees in protocol messages.

var (
	p25519 = new(big.Int).Sub(
		new(big.Int).Lsh(big.NewInt(1), 255),
		big.NewInt(19),
	)
	// (p25519 - 1) / 2
	pMinus1Over2 = new(big.Int).Rsh(new(big.Int).Sub(p25519, big.NewInt(1)), 1)
	bigA         = big.NewInt(486662)
	bigZ         = big.NewInt(2)
	bigZero      = big.NewInt(0)
	bigOne       = big.NewInt(1)
)

func expandMessageXMDSHA512(msg, dst []byte, lenInBytes int) []byte {
	// RFC 9380 §5.4.1 expand_message_xmd with SHA-512 (b_in_bytes=64, s_in_bytes=128).
	bInBytes := 64
	ell := (lenInBytes + bInBytes - 1) / bInBytes

	dstPrime := make([]byte, len(dst)+1)
	copy(dstPrime, dst)
	dstPrime[len(dst)] = byte(len(dst))

	zPad := make([]byte, 128) // SHA-512 block size

	var lenIB [2]byte
	binary.BigEndian.PutUint16(lenIB[:], uint16(lenInBytes))

	b0Input := make([]byte, 0, 128+len(msg)+2+1+len(dstPrime))
	b0Input = append(b0Input, zPad...)
	b0Input = append(b0Input, msg...)
	b0Input = append(b0Input, lenIB[:]...)
	b0Input = append(b0Input, 0x00)
	b0Input = append(b0Input, dstPrime...)
	b0 := wolfcrypt.SHA512(b0Input)

	b1Input := make([]byte, 0, 64+1+len(dstPrime))
	b1Input = append(b1Input, b0[:]...)
	b1Input = append(b1Input, 0x01)
	b1Input = append(b1Input, dstPrime...)
	b1 := wolfcrypt.SHA512(b1Input)

	pseudoRandomBytes := make([]byte, 0, ell*bInBytes)
	pseudoRandomBytes = append(pseudoRandomBytes, b1[:]...)

	prev := b1
	for i := 2; i <= ell; i++ {
		xored := [64]byte{}
		for j := range xored {
			xored[j] = b0[j] ^ prev[j]
		}
		biInput := make([]byte, 0, 64+1+len(dstPrime))
		biInput = append(biInput, xored[:]...)
		biInput = append(biInput, byte(i))
		biInput = append(biInput, dstPrime...)
		bi := wolfcrypt.SHA512(biInput)
		pseudoRandomBytes = append(pseudoRandomBytes, bi[:]...)
		prev = bi
	}

	return pseudoRandomBytes[:lenInBytes]
}

func bytesToFieldElement(b []byte) *big.Int {
	// RFC 9380 §4 OS2IP, then reduce mod p
	padded := make([]byte, 48)
	copy(padded[48-len(b):], b)
	x := new(big.Int).SetBytes(padded)
	return x.Mod(x, p25519)
}

func isSquareGFp(u *big.Int) bool {
	// Euler's criterion: u^((p-1)/2) mod p == 1 (0 is also a square)
	e := new(big.Int).Exp(u, pMinus1Over2, p25519)
	return e.Cmp(bigZero) == 0 || e.Cmp(bigOne) == 0
}

func modInverse(u *big.Int) *big.Int {
	return new(big.Int).ModInverse(u, p25519)
}

func mapToCurveElligator2(u *big.Int) *big.Int {
	// RFC 9380 §6.7.1 map_to_curve_elligator2_curve25519
	// A = 486662, Z = 2
	tv1 := new(big.Int).Mul(u, u)
	tv1.Mod(tv1, p25519)

	tv2 := new(big.Int).Mul(bigZ, tv1)
	tv2.Mod(tv2, p25519)

	// x1 = -A / (1 + tv2)
	denom := new(big.Int).Add(bigOne, tv2)
	denom.Mod(denom, p25519)

	var x1 *big.Int
	if denom.Cmp(bigZero) == 0 {
		// if 1 + Z*u^2 == 0, x1 = A (special case per RFC 9380)
		x1 = new(big.Int).Set(bigA)
	} else {
		negA := new(big.Int).Neg(bigA)
		negA.Mod(negA, p25519)
		x1 = new(big.Int).Mul(negA, modInverse(denom))
		x1.Mod(x1, p25519)
	}

	// gx1 = x1^3 + A*x1^2 + x1
	x1sq := new(big.Int).Mul(x1, x1)
	x1sq.Mod(x1sq, p25519)

	gx1 := new(big.Int).Mul(x1sq, x1)
	gx1.Mod(gx1, p25519)

	t := new(big.Int).Mul(bigA, x1sq)
	t.Mod(t, p25519)
	gx1.Add(gx1, t)
	gx1.Add(gx1, x1)
	gx1.Mod(gx1, p25519)

	var x *big.Int
	if isSquareGFp(gx1) {
		x = x1
	} else {
		// x2 = -A - x1
		x = new(big.Int).Neg(bigA)
		x.Sub(x, x1)
		x.Mod(x, p25519)
	}
	return x
}

func hashToCurveX25519(msg, dst []byte) []byte {
	// curve25519_XMD:SHA-512_ELL2_NU_ per RFC 9380 §6.7.2 (single-hash variant).
	// _NU_ (non-uniform) suffices for CPace: the generator has unknown DLOG w.r.t. the
	// basepoint, which is the property CPace requires. The full _RO_ variant additionally
	// provides indifferentiability but requires Curve25519 point addition, adding complexity
	// with no security benefit for the CPace use case.
	// lenInBytes = 48 (one field element for Curve25519, L=ceil((255+128)/8)=48)
	uBytes := expandMessageXMDSHA512(msg, dst, 48)
	u := bytesToFieldElement(uBytes)
	x := mapToCurveElligator2(u)

	// Encode as 32-byte little-endian X25519 wire format
	xBytes := x.Bytes()
	out := make([]byte, 32)
	// big.Int.Bytes() is big-endian; X25519 is little-endian
	for i := range xBytes {
		if i >= 32 {
			break
		}
		out[i] = xBytes[len(xBytes)-1-i]
	}
	return out
}
