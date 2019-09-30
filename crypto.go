package macaroon

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"fmt"
	"hash"
	"io"
	
	"golang.org/x/crypto/nacl/secretbox"
)

func HmacSha256Signer(key []byte, m *Macaroon) ([]byte, error) {
	if len(key) != 32 {
		return nil, fmt.Errorf("wrong key length: %d", len(key))
	}
	sig := KeyedHash(key, m.Id())
	
	for _, cav := range m.Caveats() {
		if len(cav.VerificationId) == 0 {
			sig = KeyedHash(sig, cav.Id)
		} else {
			sig = keyedHash2(sig, cav.VerificationId, cav.Id)
		}
	}
	return sig, nil
}

func HmacSha256SignatureVerify(key []byte, m Macaroon) error {
	s := m.Signature()
	err := m.Sign(key, HmacSha256Signer)
	if err != nil {
		return fmt.Errorf("signature error: %v", err)
	}
	if bytes.Equal(s, m.sig) {
		return nil
	} else {
		return fmt.Errorf("wrong signature")
	}
}

func KeyedHash(key []byte, text []byte) []byte {
	h := keyedHasher(key)
	h.Write([]byte(text))
	var sum [hashLen]byte
	hashSum(h, &sum)
	return sum[:]
}

func keyedHash2(key []byte, d1, d2 []byte) []byte {
	var data [hashLen * 2]byte
	copy(data[0:], KeyedHash(key, d1)[:])
	copy(data[hashLen:], KeyedHash(key, d2)[:])
	return KeyedHash(key, data[:])
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
