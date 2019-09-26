package macaroon_pass

import (
	"crypto/rand"
	"fmt"
	"github.com/ArrowPass/macaroon"
)

type Environment struct {
	Key []byte
	Signer func(key []byte, macaroon *macaroon.Macaroon) ([]byte, error)
}

func RandomKey(size int) ([]byte, error) {
	buf := make([]byte, size)
	_, e := rand.Read(buf)
	if e != nil {
		return nil, fmt.Errorf("cannot generate random key: %v", e);
	}
	return buf, nil
}
