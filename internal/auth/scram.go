// Package auth implements XMPP SASL mechanisms: SCRAM-SHA-{256,512}[-PLUS] and PLAIN.
package auth

import (
	"bytes"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"

	"github.com/danielinux/xmppqr/internal/wolfcrypt"
)

type Mechanism string

const (
	SCRAMSHA256     Mechanism = "SCRAM-SHA-256"
	SCRAMSHA512     Mechanism = "SCRAM-SHA-512"
	SCRAMSHA256Plus Mechanism = "SCRAM-SHA-256-PLUS"
	SCRAMSHA512Plus Mechanism = "SCRAM-SHA-512-PLUS"
	Plain           Mechanism = "PLAIN"
)

type ChannelBinding interface {
	Type() string
	Data() []byte
}

type StoredCreds struct {
	Salt      []byte
	Iter      int
	StoredKey []byte
	ServerKey []byte
}

type lookupFunc func(username string) (*StoredCreds, error)

type scramState int

const (
	stateFirst scramState = iota
	stateFinal
	stateDone
)

type Server struct {
	mech      Mechanism
	lookup    lookupFunc
	cb        ChannelBinding
	state     scramState
	username  string
	clientNonce string
	serverNonce string
	authMsg   string
	creds     *StoredCreds
	mechList  []string
}

func NewServer(mech Mechanism, lookup lookupFunc, cb ChannelBinding) (*Server, error) {
	switch mech {
	case SCRAMSHA256, SCRAMSHA512, SCRAMSHA256Plus, SCRAMSHA512Plus:
	default:
		return nil, fmt.Errorf("auth: unsupported mechanism %s", mech)
	}
	if (mech == SCRAMSHA256Plus || mech == SCRAMSHA512Plus) && cb == nil {
		return nil, errors.New("auth: channel binding required for PLUS variants")
	}
	serverNonce, err := generateNonce(24)
	if err != nil {
		return nil, err
	}
	return &Server{
		mech:        mech,
		lookup:      lookup,
		cb:          cb,
		state:       stateFirst,
		serverNonce: serverNonce,
	}, nil
}

func (s *Server) BindMechanismList(mechs []string) {
	s.mechList = mechs
}

func (s *Server) Username() string { return s.username }

func (s *Server) Step(in []byte) ([]byte, bool, error) {
	switch s.state {
	case stateFirst:
		return s.stepFirst(in)
	case stateFinal:
		return s.stepFinal(in)
	default:
		return nil, false, errors.New("auth: exchange already complete")
	}
}

func (s *Server) stepFirst(in []byte) ([]byte, bool, error) {
	// client-first-message: gs2-header + client-first-message-bare
	// gs2-header: "n,," or "y,," or "p=<cbtype>,,"
	msg := string(in)
	gs2End := strings.Index(msg, ",,")
	if gs2End < 0 {
		return nil, false, errors.New("auth: malformed client-first: no gs2 header")
	}
	gs2Header := msg[:gs2End]
	clientFirstBare := msg[gs2End+2:]

	if err := s.validateGS2Header(gs2Header); err != nil {
		return nil, false, err
	}

	fields := parseKV(clientFirstBare)
	n, ok := fields["n"]
	if !ok {
		return nil, false, errors.New("auth: missing username in client-first")
	}
	r, ok := fields["r"]
	if !ok {
		return nil, false, errors.New("auth: missing nonce in client-first")
	}
	s.username = n
	s.clientNonce = r

	creds, err := s.lookup(n)
	if err != nil {
		return nil, false, fmt.Errorf("auth: lookup failed: %w", err)
	}
	s.creds = creds

	combinedNonce := r + s.serverNonce
	saltB64 := base64.StdEncoding.EncodeToString(creds.Salt)
	serverFirst := fmt.Sprintf("r=%s,s=%s,i=%d", combinedNonce, saltB64, creds.Iter)

	// authMessage = client-first-message-bare + "," + server-first-message + "," + client-final-message-without-proof
	// We store the prefix; client-final part is appended in stepFinal.
	s.authMsg = clientFirstBare + "," + serverFirst
	s.state = stateFinal
	return []byte(serverFirst), false, nil
}

func (s *Server) stepFinal(in []byte) ([]byte, bool, error) {
	msg := string(in)
	// Split off client-proof: everything before ",p="
	pIdx := strings.LastIndex(msg, ",p=")
	if pIdx < 0 {
		return nil, false, errors.New("auth: missing proof in client-final")
	}
	clientFinalWithoutProof := msg[:pIdx]
	proofB64 := msg[pIdx+3:]

	proof, err := base64.StdEncoding.DecodeString(proofB64)
	if err != nil {
		return nil, false, errors.New("auth: invalid proof encoding")
	}

	fields := parseKV(clientFinalWithoutProof)
	cbindB64, ok := fields["c"]
	if !ok {
		return nil, false, errors.New("auth: missing channel-binding in client-final")
	}
	cbindData, err := base64.StdEncoding.DecodeString(cbindB64)
	if err != nil {
		return nil, false, errors.New("auth: invalid cbind encoding")
	}
	if err := s.verifyChannelBinding(cbindData); err != nil {
		return nil, false, err
	}

	r, ok := fields["r"]
	if !ok {
		return nil, false, errors.New("auth: missing nonce in client-final")
	}
	expectedNonce := s.clientNonce + s.serverNonce
	if r != expectedNonce {
		return nil, false, errors.New("auth: nonce mismatch")
	}

	// XEP-0474: verify mechanism list hash if bound
	if len(s.mechList) > 0 {
		hB64, hasH := fields["h"]
		if !hasH {
			return nil, false, errors.New("auth: missing mechanism list hash (XEP-0474)")
		}
		hBytes, err := base64.StdEncoding.DecodeString(hB64)
		if err != nil {
			return nil, false, errors.New("auth: invalid mechanism hash encoding")
		}
		expected := ComputeMechanismListHash(s.mechList)
		if !bytes.Equal(hBytes, expected) {
			return nil, false, errors.New("auth: mechanism list hash mismatch (downgrade detected)")
		}
	}

	authMessage := s.authMsg + "," + clientFinalWithoutProof

	hmacFn, hFn, _ := s.hashFunctions()

	// Recover ClientKey = ClientProof XOR HMAC(StoredKey, authMessage)
	clientSig, err := hmacFn(s.creds.StoredKey, []byte(authMessage))
	if err != nil {
		return nil, false, err
	}
	if len(proof) != len(clientSig) {
		return nil, false, errors.New("auth: proof length mismatch")
	}
	clientKey := make([]byte, len(proof))
	for i := range proof {
		clientKey[i] = proof[i] ^ clientSig[i]
	}
	storedKeyCheck := hFn(clientKey)
	if !bytes.Equal(storedKeyCheck, s.creds.StoredKey) {
		return nil, false, errors.New("auth: authentication failed")
	}

	// Compute ServerSignature
	serverSig, err := hmacFn(s.creds.ServerKey, []byte(authMessage))
	if err != nil {
		return nil, false, err
	}
	serverFinal := "v=" + base64.StdEncoding.EncodeToString(serverSig)
	s.state = stateDone
	return []byte(serverFinal), true, nil
}

func (s *Server) validateGS2Header(gs2 string) error {
	isPlus := s.mech == SCRAMSHA256Plus || s.mech == SCRAMSHA512Plus
	if isPlus {
		prefix := "p=" + s.cb.Type()
		if gs2 != prefix {
			return fmt.Errorf("auth: expected gs2 header %q, got %q", prefix, gs2)
		}
	} else {
		if gs2 != "n" && gs2 != "y" {
			return fmt.Errorf("auth: unexpected gs2 header %q for non-PLUS mechanism", gs2)
		}
	}
	return nil
}

func (s *Server) verifyChannelBinding(cbindData []byte) error {
	isPlus := s.mech == SCRAMSHA256Plus || s.mech == SCRAMSHA512Plus
	if !isPlus {
		return nil
	}
	// cbind-input = gs2-header + channel-binding-data
	gs2Header := "p=" + s.cb.Type() + ",,"
	expected := append([]byte(gs2Header), s.cb.Data()...)
	if !bytes.Equal(cbindData, expected) {
		return errors.New("auth: channel binding data mismatch")
	}
	return nil
}

func (s *Server) hashFunctions() (
	hmacFn func(key, msg []byte) ([]byte, error),
	hFn func(data []byte) []byte,
	digestLen int,
) {
	switch s.mech {
	case SCRAMSHA512, SCRAMSHA512Plus:
		return wolfcrypt.HMACSHA512, func(d []byte) []byte {
			h := wolfcrypt.SHA512(d)
			return h[:]
		}, 64
	default:
		return wolfcrypt.HMACSHA256, func(d []byte) []byte {
			h := wolfcrypt.SHA256(d)
			return h[:]
		}, 32
	}
}

func parseKV(s string) map[string]string {
	m := make(map[string]string)
	for _, part := range strings.Split(s, ",") {
		idx := strings.IndexByte(part, '=')
		if idx < 0 {
			continue
		}
		m[part[:idx]] = part[idx+1:]
	}
	return m
}

func generateNonce(n int) (string, error) {
	b := make([]byte, n)
	if _, err := wolfcrypt.Read(b); err != nil {
		return "", err
	}
	return base64.RawStdEncoding.EncodeToString(b), nil
}
