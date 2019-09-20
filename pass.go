package macaroon_pass

import (
	"crypto/rand"
	"fmt"
)

type Environment struct {
	Key []byte
}

func RandomKey(size int) ([]byte, error) {
	buf := make([]byte, size)
	_, e := rand.Read(buf)
	if e != nil {
		return nil, fmt.Errorf("Cannot generate random key: %v", e);
	}
	return buf, nil
}
