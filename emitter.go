package macaroon_pass

import (
	"crypto/rand"
	"fmt"
	"gopkg.in/macaroon.v2"
	"strings"
)

//const KeyLen = 32
//
//type SimpleKey [KeyLen]byte
//
//type KeyPair struct {
//	PrivateKey SimpleKey
//	PublicKey SimpleKey
//}


type Environment struct {
	Key []byte
	//KeyPair KeyPair
	operationList []string
}

func RandomKey(size int) ([]byte, error) {
	buf := make([]byte, size)
	_, e := rand.Read(buf)
	if e != nil {
		return nil, fmt.Errorf("Cannot generate random key: %v", e);
	}
	return buf, nil
}

func (env* Environment) makeId (ops []string) ([]byte, error) {
	strId := strings.Join(ops, "|")
	id := []byte(strId)

	//cipher, err := aes.NewCipher(env.Key)
	//if err != nil {
	//	return nil, fmt.Errorf("Cannot generate macaroon id: %v", err)
	//}
	//
	//enc := cipher2.NewCBCEncrypter(cipher, nil)
	//
	//
	//err = cipher.Encrypt

	return id, nil
}

func (env* Environment) EmitMacaroon (ops []string) (*macaroon.Macaroon, error) {
	id, err := env.makeId(ops)
	if err != nil {
		return nil, fmt.Errorf("Cannot create macaroon id: %v", err)
	}
	m, err := macaroon.New(env.Key, id, "", macaroon.V2)
	if err != nil {
		return nil, fmt.Errorf("Cannot create macaroon: %v", err)
	}
	return m, nil
}



