package macaroon_pass

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"github.com/decred/dcrd/dcrec/secp256k1"
	"hash"
	"io"
	"log"

	"golang.org/x/crypto/nacl/secretbox"
)


func RandomKey(size int) ([]byte, error) {
	buf := make([]byte, size)
	_, e := rand.Read(buf)
	if e != nil {
		return nil, fmt.Errorf("cannot generate random key: %v", e);
	}
	return buf, nil
}


func calcMacaroonHash(m *Macaroon) [sha256.Size]byte {
	msg := m.Id()

	for _, cav := range m.Caveats() {
		msg = append(msg, cav.Id...)
		if cav.IsThirdParty() {
			msg = append(msg, cav.VerificationId...)
		}
	}

	hash := sha256.Sum256(msg)
	return hash
}

type Signer interface {
	SignMacaroon(m *Macaroon) error
	SignData([]byte) ([]byte, error)
}

type EcdsaSigner struct {
	priv *secp256k1.PrivateKey
}

func NewEcdsaSigner(key []byte) *EcdsaSigner {
	priv, _ := secp256k1.PrivKeyFromBytes(key)
	return &EcdsaSigner{priv:priv}
}

func (s *EcdsaSigner) SignData(data []byte) ([]byte, error) {
	hash := sha256.Sum256(data)
	sig, err := s.priv.Sign(hash[:])
	if err != nil {
		return nil, fmt.Errorf("cannot make ECDSA signature: %v", err)
	}
	return sig.Serialize(), nil
}

func (s *EcdsaSigner) SignMacaroon (m *Macaroon) error {
	hash := calcMacaroonHash(m)

	sig, err := s.priv.Sign(hash[:])
	if err != nil {
		return fmt.Errorf("cannot make ECDSA signature: %v", err)
	}
	m.sig = sig.Serialize()
	return nil
}

func EcdsaSignatureVerify(pubKey []byte, m *Macaroon) error {
	s := m.Signature()
	if s == nil {
		return fmt.Errorf("signature is nil")
	}

	sig, err := secp256k1.ParseSignature(s)
	if err != nil {
		return fmt.Errorf("cannot parse signature: %v", err)
	}

	hash := calcMacaroonHash(m)
	key, err := secp256k1.ParsePubKey(pubKey)
	if err != nil {
		return fmt.Errorf("cannot parse public key: %v", err)
	}

	if sig.Verify(hash[:], key) {
		return nil
	} else {
		return fmt.Errorf("wrong signature")
	}
}
type HmacSha256Signer struct {
	key      []byte
	macaroon *Macaroon
	nextStep int
}

func NewHmacSha256Signer(key []byte) (*HmacSha256Signer, error) {
	if len(key) == 0 {
		return nil, fmt.Errorf("no key was passed when create HMAC SHA256 signer")
	}
	return &HmacSha256Signer{key: key}, nil
}

func DeriveHmacSha256Signer(m *Macaroon) (*HmacSha256Signer, error) {
	if m == nil {
		return nil, fmt.Errorf("no macaroon was passed when derive HMAC SHA256 signer")
	}
	if len(m.sig) == 0 {
		return nil, fmt.Errorf("can not use unsigned macaroon to derive HMAC SHA256 signer")
	}

	return &HmacSha256Signer{
		key:      nil,
		macaroon: m,
		nextStep: len(m.caveats) + 1,
	}, nil
}

func makeHmacSha256Signature(key []byte, m *Macaroon, step int) ([][]byte, error) {

	signatures := [][]byte(nil)

	if step == 0 {
		signatures = append(signatures, HmacSha256KeyedHash(key, m.Id()))
		step++
	} else if m.sig != nil {
		signatures = append(signatures, m.sig)
	} else {
		return nil, fmt.Errorf("wrong HMAC SHA256 signer state")
	}

	var i int
	for i = step-1; i < len(m.caveats); i++ {
		cav := m.caveats[i]
		data := []byte(nil)
		if len(cav.VerificationId) != 0 {
			data = append(data, cav.VerificationId...)
		}
		data = append (data, cav.Id...)

		log.Printf("====== Data to sign: " + hex.EncodeToString(data))

		signatures = append(signatures, HmacSha256KeyedHash(signatures[len(signatures) - 1], data))
	}
	return signatures, nil
}

func (s* HmacSha256Signer) SignMacaroon(m *Macaroon) error {
	if s.macaroon != nil && s.macaroon != m {
		return fmt.Errorf("can not sign another macaroon")
	}
	if s.macaroon != nil && s.macaroon.sig == nil {
		return fmt.Errorf("wrong HMAC SHA256 signer state")
	}

	signatures, err := makeHmacSha256Signature(s.key, m, s.nextStep)
	if err != nil {
		return err
	}

	if s.macaroon == nil {
		s.macaroon = m
	}

	s.macaroon.sig = signatures[len(signatures) - 1]
	s.nextStep = len(m.caveats) + 1

	return nil
}

func (s* HmacSha256Signer) SignData(data []byte) ([]byte, error) {
	if s.macaroon == nil || s.macaroon.sig == nil {
		return nil, fmt.Errorf("there is still no incremental signature available")
	}
	return HmacSha256KeyedHash(s.macaroon.sig , data), nil
}

func HmacSha256SignatureVerify(key []byte, m *Macaroon) error {
	sig, err := makeHmacSha256Signature(key, m, 0)
	if err != nil {
		return fmt.Errorf("signature error: %v", err)
	}
	if hmac.Equal(sig[len(sig) - 1], m.sig) {
		return nil
	} else {
		return fmt.Errorf("wrong signature")
	}
}

func HmacSha256KeyedHash(key []byte, text []byte) []byte {
	h := keyedHasher(key)
	h.Write([]byte(text))
	var sum [hashLen]byte
	hashSum(h, &sum)
	return sum[:]
}

func keyedHash2(key []byte, d1, d2 []byte) []byte {
	var data [hashLen * 2]byte
	copy(data[0:], HmacSha256KeyedHash(key, d1)[:])
	copy(data[hashLen:], HmacSha256KeyedHash(key, d2)[:])
	return HmacSha256KeyedHash(key, data[:])
}

func keyedHasher(key []byte) hash.Hash {
	return hmac.New(sha256.New, key)
}

var keyGen = []byte("macaroons-key-generator")

// MakeKey derives a fixed length key from a variable
// length key. The keyGen constant is the same
// as that used in libmacaroons.
func MakeKey(variableKey []byte) []byte {
	h := hmac.New(sha256.New, keyGen)
	h.Write(variableKey)
	var key [keyLen]byte
	hashSum(h, &key)
	return key[:]
}

// hashSum calls h.Sum to put the sum into
// the given destination. It also sanity
// checks that the result really is the expected
// size.
func hashSum(h hash.Hash, dest *[hashLen]byte) {
	r := h.Sum(dest[:0])
	if len(r) != len(dest) {
		panic("hash size inconsistency")
	}
}

const (
	keyLen   = 32
	nonceLen = 24
	hashLen  = sha256.Size
)

func newNonce(r io.Reader) (*[nonceLen]byte, error) {
	var nonce [nonceLen]byte
	_, err := r.Read(nonce[:])
	if err != nil {
		return nil, fmt.Errorf("cannot generate random bytes: %v", err)
	}
	return &nonce, nil
}

func encrypt(key *[keyLen]byte, text *[hashLen]byte, r io.Reader) ([]byte, error) {
	nonce, err := newNonce(r)
	if err != nil {
		return nil, err
	}
	out := make([]byte, 0, len(nonce)+secretbox.Overhead+len(text))
	out = append(out, nonce[:]...)
	return secretbox.Seal(out, text[:], nonce, key), nil
}

func decrypt(key *[keyLen]byte, ciphertext []byte) (*[hashLen]byte, error) {
	if len(ciphertext) < nonceLen+secretbox.Overhead {
		return nil, fmt.Errorf("message too short")
	}
	var nonce [nonceLen]byte
	copy(nonce[:], ciphertext)
	ciphertext = ciphertext[nonceLen:]
	text, ok := secretbox.Open(nil, ciphertext, &nonce, key)
	if !ok {
		return nil, fmt.Errorf("decryption failure")
	}
	if len(text) != hashLen {
		return nil, fmt.Errorf("decrypted text is wrong length")
	}
	var rtext [hashLen]byte
	copy(rtext[:], text)
	return &rtext, nil
}
