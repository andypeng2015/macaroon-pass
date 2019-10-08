package macaroon_pass

import (
	"crypto/rand"
	"crypto/sha256"
	"fmt"
	"github.com/decred/dcrd/dcrec/secp256k1"
)

type Signer func(key []byte, macaroon *Macaroon) ([]byte, error)

type Environment struct {
	Key []byte
	Signer Signer
}

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

func EcdsaSigner(key []byte, m *Macaroon) ([]byte, error) {
	
	priv, _ := secp256k1.PrivKeyFromBytes(key)
	
	hash := calcMacaroonHash(m)
	
	sig, err := priv.Sign(hash[:])
	if err != nil {
		return nil, fmt.Errorf("cannot make Schnorr sign: %v", err)
	}
	return sig.Serialize(), nil
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
