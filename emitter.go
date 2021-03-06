package macaroon_pass

import (
	"encoding/hex"
	"fmt"
	"log"
)

// Emitter is the abstraction over macaroon which allows to create new macaroons with different encryption schemes
// Common usage sample:
// macId := getCardId()
// macKey := GetMacKey(macId)
// invAddr := GetInvoiceAddr()
// op := []byte("invoice=" + invAddr)
// emt := NewEmitter(macKey, HmacSha256Signer, macId)
// emt.AuthorizeOperations([][]byte{op})
//
// delegatedOp := []byte(getMerchantId())
// nonce := getCardNonce()
// emt.DelegateAuthorization(delegatedOp, "das", nonce)
// macaroon, err := emt.Emit()
//
// discharge := RequestDischargeMacaroon()
//
// marshaller := SliceMarshaller{macaroon, discharge}
// bin, err := marshaller.MarshalBinary()


type thirdPartyOp struct {
	operation []byte
	location  string
	nonce     []byte
}

type Emitter struct {
	macaroonBase *Macaroon
	signer       Signer
	selector     []byte
	operations   [][]byte
	delegatedOps []*thirdPartyOp
	
}

func NewEmitter (signer Signer,  selector []byte) *Emitter {
	res := Emitter{
		signer:       signer,
		selector:     selector,
		operations:   make([][]byte, 0),
		delegatedOps: make([]*thirdPartyOp, 0),
	}
	
	return &res
}

func RecreateEmitter(signer Signer, m *Macaroon) *Emitter {
	res := Emitter{
		macaroonBase: m,
		signer:       signer,
		selector:     nil,
		operations:   nil,
		delegatedOps: nil,
	}
	return &res
}

func (emt *Emitter) AuthorizeOperation (op []byte) error {

	newOp := make([]byte, len(op))
	copy(newOp, op)
	emt.operations = append(emt.operations, newOp)

	log.Printf("New caveat: %v", string(op))

	return nil
}

func (emt *Emitter) DelegateAuthorization(op []byte, location string, verificationId []byte) error {
	d := thirdPartyOp{
		operation: make([]byte, len(op)),
		nonce:     make([]byte, len(verificationId)),
	}

	copy(d.operation, op)
	copy(d.nonce, verificationId)

	locationBytes := []byte(location)
	locationCopyBytes := make([]byte, len(locationBytes))
	copy(locationCopyBytes, locationBytes)

	d.location = string(locationCopyBytes)

	log.Printf("New caveat: %v, location: %v, vid: %v", string(op), location, hex.EncodeToString(verificationId))

	emt.delegatedOps = append(emt.delegatedOps, &d)

	return nil
}

func (emt* Emitter) EmitMacaroon () (*Macaroon, error) {
	var err error
	m := emt.macaroonBase
	if m == nil {
		m, err = New(emt.selector, "", V2)
		if err != nil {
			return nil, fmt.Errorf("cannot create macaroon: %v", err)
		}
	}
	for _, v := range emt.operations {
		log.Printf("Adding caveat: %v", hex.EncodeToString(v))
		err = m.AddFirstPartyCaveat(v)
		if err != nil {
			return nil, fmt.Errorf("cannot add first-party caveat: %v", err)
		}
	}
	for _, d := range emt.delegatedOps {
		log.Printf("Adding 3-rd party caveat: %v, loc: %v, vid: %v", string(d.operation), d.location, hex.EncodeToString(d.nonce))

		err = emt.signer.SignMacaroon(m)
		if err != nil {
			return nil, fmt.Errorf("cannot sign macaroon: %v", err)
		}

		err = m.AddCaveat(d.operation, d.nonce, d.location)
		if err != nil {
			return nil, fmt.Errorf("cannot add third-party caveat: %v", err)
		}
	}
	err = emt.signer.SignMacaroon(m)
	if err != nil {
		return nil, fmt.Errorf("cannot sign macaroon: %v", err)
	}

	emt.macaroonBase = m

	mCopy := *m

	return &mCopy, nil
}





