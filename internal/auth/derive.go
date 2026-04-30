package auth

import (
	"fmt"

	"github.com/danielinux/xmppqr/internal/wolfcrypt"
)

func hashIDForMech(mech Mechanism) (int, error) {
	switch mech {
	case SCRAMSHA512, SCRAMSHA512Plus:
		return wolfcrypt.HashSHA512, nil
	case SCRAMSHA256, SCRAMSHA256Plus:
		return wolfcrypt.HashSHA256, nil
	default:
		return 0, fmt.Errorf("auth: unsupported mechanism %s", mech)
	}
}

func deriveSaltedPassword(password, salt []byte, iter int, mech Mechanism) ([]byte, error) {
	hashID, err := hashIDForMech(mech)
	if err != nil {
		return nil, err
	}
	keyLen := 32
	if hashID == wolfcrypt.HashSHA512 {
		keyLen = 64
	}
	return wolfcrypt.PBKDF2(password, salt, iter, keyLen, hashID)
}

func DeriveSCRAMCreds(password, salt []byte, iter int, mech Mechanism) (*StoredCreds, error) {
	hashID, err := hashIDForMech(mech)
	if err != nil {
		return nil, err
	}
	keyLen := 32
	if hashID == wolfcrypt.HashSHA512 {
		keyLen = 64
	}

	saltedPassword, err := wolfcrypt.PBKDF2(password, salt, iter, keyLen, hashID)
	if err != nil {
		return nil, err
	}

	var hmacFn func(key, msg []byte) ([]byte, error)
	var hFn func([]byte) []byte
	if hashID == wolfcrypt.HashSHA512 {
		hmacFn = wolfcrypt.HMACSHA512
		hFn = func(d []byte) []byte { h := wolfcrypt.SHA512(d); return h[:] }
	} else {
		hmacFn = wolfcrypt.HMACSHA256
		hFn = func(d []byte) []byte { h := wolfcrypt.SHA256(d); return h[:] }
	}

	clientKey, err := hmacFn(saltedPassword, []byte("Client Key"))
	if err != nil {
		return nil, err
	}
	storedKey := hFn(clientKey)

	serverKey, err := hmacFn(saltedPassword, []byte("Server Key"))
	if err != nil {
		return nil, err
	}

	return &StoredCreds{
		Salt:      salt,
		Iter:      iter,
		StoredKey: storedKey,
		ServerKey: serverKey,
	}, nil
}
