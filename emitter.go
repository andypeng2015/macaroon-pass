package macaroon_pass

import (
	"fmt"
	"gopkg.in/macaroon.v2"
)

//const KeyLen = 32
//
//type SimpleKey [KeyLen]byte
//
//type KeyPair struct {
//	PrivateKey SimpleKey
//	PublicKey SimpleKey
//}

type Emitter struct {
	Environment
	selector []byte
	operationList [][]byte
}

func NewEmitter (key []byte, selector []byte) *Emitter {
	res := Emitter{
		Environment: Environment{
			Key:           key,
		},
		selector:    selector,
	}
	return &res
}

func (emt *Emitter) DeclareOperations (operations [][]byte) {
	emt.operationList = operations
}

/*
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
*/
func (emt* Emitter) EmitMacaroon () (*macaroon.Macaroon, error) {
	m, err := macaroon.New(emt.Key, emt.selector, "", macaroon.V2)
	if err != nil {
		return nil, fmt.Errorf("Cannot create macaroon: %v", err)
	}
	for _, v := range emt.operationList {
		err = m.AddFirstPartyCaveat(v)
		if err != nil {
			return nil, fmt.Errorf("Cannot add first-party caveat: %v", err)
		}
	}
	return m, nil
}





