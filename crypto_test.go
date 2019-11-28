package macaroon_pass

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"log"
	"testing"

	qt "github.com/frankban/quicktest"
	"golang.org/x/crypto/nacl/secretbox"
)

var testCryptKey = &[hashLen]byte{'k', 'e', 'y'}
var testCryptText = &[hashLen]byte{'t', 'e', 'x', 't'}

func TestEncDec(t *testing.T) {
	c := qt.New(t)
	b, err := encrypt(testCryptKey, testCryptText, rand.Reader)
	c.Assert(err, qt.Equals, nil)
	p, err := decrypt(testCryptKey, b)
	c.Assert(err, qt.Equals, nil)
	c.Assert(string(p[:]), qt.Equals, string(testCryptText[:]))
}

func TestUniqueNonces(t *testing.T) {
	c := qt.New(t)
	nonces := make(map[string]struct{})
	for i := 0; i < 100; i++ {
		nonce, err := newNonce(rand.Reader)
		c.Assert(err, qt.Equals, nil)
		nonces[string(nonce[:])] = struct{}{}
	}
	c.Assert(nonces, qt.HasLen, 100, qt.Commentf("duplicate nonce detected"))
}

type ErrorReader struct{}

func (*ErrorReader) Read([]byte) (int, error) {
	return 0, fmt.Errorf("fail")
}

func TestBadRandom(t *testing.T) {
	c := qt.New(t)
	_, err := newNonce(&ErrorReader{})
	c.Assert(err, qt.ErrorMatches, "^cannot generate random bytes:.*")

	_, err = encrypt(testCryptKey, testCryptText, &ErrorReader{})
	c.Assert(err, qt.ErrorMatches, "^cannot generate random bytes:.*")
}

func TestBadCiphertext(t *testing.T) {
	c := qt.New(t)
	buf := randomBytes(nonceLen + secretbox.Overhead)
	for i := range buf {
		_, err := decrypt(testCryptKey, buf[0:i])
		c.Assert(err, qt.ErrorMatches, "message too short")
	}
	_, err := decrypt(testCryptKey, buf)
	c.Assert(err, qt.ErrorMatches, "decryption failure")
}

func randomBytes(n int) []byte {
	buf := make([]byte, n)
	if _, err := rand.Reader.Read(buf); err != nil {
		panic(err)
	}
	return buf
}

func TestHmacSha256KeyedHash(t *testing.T) {
	c := qt.New(t)
	var testKey = "00112233445566778899AABBCCDDEEFF00112233445566778899AABBCCDDEEFF"
	var testData = "22aa56f9398857389812982183123412374723472134981290312933edfc7c92d921de7d67ededee8c"
	var testResult = "e78b43cfb2d407b1f71886447a2cd2ef89b0c5891c1ba99ac4216bfc2aa1f0fc"

	decodedKey, errKey := hex.DecodeString(testKey)
	if errKey != nil {
		log.Fatal(errKey)
	}

	decodedData, errData := hex.DecodeString(testData)
	if errData != nil {
		log.Fatal(errData)
	}

	res := HmacSha256KeyedHash(decodedKey, decodedData)

	encodedStr := hex.EncodeToString(res)

	c.Assert(encodedStr, qt.DeepEquals, testResult)
}