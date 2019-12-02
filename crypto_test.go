package macaroon_pass

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"log"
	"strings"
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

func TestMakeHmacSha256Signature(t *testing.T) {
	c := qt.New(t)

	var cardIdHex = "3030303030303030303030303030303030303030303033334130383130303034"
	var signature = "4AF05451CD8B86E8740B3AFD384B92076FF3DE68E2570EF9BD2CE4F9E290AB8B"
	var verificationId = "FF8299AF1C704B46B96342294480DECEB29F5431C338491840940C17DB5F99E3"
	var paymentString = "payment lntb120u1pw7fh3spp5j5d27q84eykgz6l9lj86gpu9fpnnn7qp6d3ux24vufgjjrrpd6dsdp9g9e8ymmh2pshxueqw3jhxapqwp6hycmgv9ek2cqzpgxqzfvuh99cjcz74wpnlne4w788fsjx0m9jgv365u9hem7fzrrtf2uluprnfvwnlt5pqjw9dlfd8azr8g7wdxtwg09td32008ah53axkcp77gq9pc768"
	var resultSig = "9EB690975C36E07E12F99D099D506DBEFCFA481BD18AE87FB51AFBBC0F8E7401"

	var dasCaveatId = "DAS 9FD91A9251A1D8FE55A0FDE4A87090D98E91CA0F58517F6FB2892836884B36F9"
	var amoutString = "amount 12000"

	decodedId, errId := hex.DecodeString(cardIdHex)
	if errId != nil {
		log.Fatal(errId)
	}

	decodedSig, errSig := hex.DecodeString(signature)
	if errSig != nil {
		log.Fatal(errSig)
	}

	decodedNonce, errNonce := hex.DecodeString(verificationId)
	if errNonce != nil {
		log.Fatal(errNonce)
	}

	var m Macaroon
	m.init(append([]byte(nil), decodedId...), "", V2)

	var macaroonbase = &m
	macaroonbase.sig = decodedSig

	fmt.Println("BASE MACAROON ID: " + hex.EncodeToString(macaroonbase.id))
	fmt.Println("BASE MACAROON SIG: " + hex.EncodeToString(macaroonbase.sig))
	fmt.Println("BASE MACAROON CAVEATS: " + string(len(macaroonbase.caveats)))

	// TEST 1  --------------------------------------------------------------
	/*var signer2 Signer
	signer2, _ = DeriveHmacSha256Signer(macaroonbase)

	var emitter = RecreateEmitter(signer2, macaroonbase)
	emitter.AuthorizeOperation([]byte(paymentString))
	emitter.AuthorizeOperation([]byte(amoutString))
	emitter.DelegateAuthorization([]byte(dasCaveatId), "das", decodedNonce)

	var mm *Macaroon
	mm, _ = emitter.EmitMacaroon()

	fmt.Println("SIG OUT: " + strings.ToUpper(hex.EncodeToString(mm.sig)))

	c.Assert(strings.ToUpper(hex.EncodeToString(mm.sig)), qt.DeepEquals, resultSig)*/

	// TEST 2  --------------------------------------------------------------
	/*var signer2 Signer
	signer2, _ = DeriveHmacSha256Signer(macaroonbase)

	macaroonbase.AddFirstPartyCaveat([]byte(paymentString))
	macaroonbase.AddFirstPartyCaveat([]byte(amoutString))
	signer2.SignMacaroon(macaroonbase)

	macaroonbase.AddCaveat([]byte(dasCaveatId), decodedNonce, "das")
	signer2.SignMacaroon(macaroonbase)

	fmt.Println("SIG OUT: " + strings.ToUpper(hex.EncodeToString(macaroonbase.sig)))

	c.Assert(strings.ToUpper(hex.EncodeToString(macaroonbase.sig)), qt.DeepEquals, resultSig)*/

	// TEST 3  --------------------------------------------------------------
	macaroonbase.AddFirstPartyCaveat([]byte(paymentString))
	macaroonbase.AddFirstPartyCaveat([]byte(amoutString))
	macaroonbase.AddCaveat([]byte(dasCaveatId), decodedNonce, "das")

	var key = decodedSig

	fmt.Println("BASE MACAROON SIGNATURE: " + hex.EncodeToString(decodedSig))

	var i int
	for i = 0; i < len(macaroonbase.caveats); i++ {
		cav := macaroonbase.caveats[i]
		data := []byte(nil)
		if len(cav.VerificationId) != 0 {
			data = append(data, cav.VerificationId...)
		}
		data = append (data, cav.Id...)
		key = HmacSha256KeyedHash(key, data)
		fmt.Printf("KEY(%d): %s\r\n", i, hex.EncodeToString(key))
	}

	c.Assert(strings.ToUpper(hex.EncodeToString(key)), qt.DeepEquals, resultSig)
}