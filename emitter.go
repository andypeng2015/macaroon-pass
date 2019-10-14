package macaroon_pass

import (
	"fmt"
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
	location string
	verificationId []byte
}

type Emitter struct {
	macaroonBase *Macaroon
	key          []byte
	signer       Signer
	selector     []byte
	operations   [][]byte
	delegatedOps []*thirdPartyOp
	
}

func NewEmitter (key []byte, signer func (key []byte, m *Macaroon) ([]byte, error),  selector []byte) *Emitter {
	res := Emitter{
		key:          key,
		signer:       signer,
		selector:     selector,
		operations:   make([][]byte, 0),
		delegatedOps: make([]*thirdPartyOp, 0),
	}
	
	return &res
}

func RecreateEmitter(key []byte, signer func (key []byte, m *Macaroon) ([]byte, error), m *Macaroon) *Emitter {
	res := Emitter{
		macaroonBase: m,
		key:          key,
		signer:       signer,
		selector:     nil,
		operations:   nil,
		delegatedOps: nil,
	}
	return &res
}

func (emt *Emitter) AuthorizeOperation (op []byte) error {
	emt.operations = append(emt.operations, op)
	return nil
}

func (emt *Emitter) DelegateAuthorization(op []byte, location string, verificationId []byte) {
	var d *thirdPartyOp
	d = new (thirdPartyOp)
	d.operation = op
	d.location = location
	d.verificationId = verificationId
	
	emt.delegatedOps = append(emt.delegatedOps, d)
}

func (emt* Emitter) EmitMacaroon () (*Marshaller, error) {
	var err error
	m := emt.macaroonBase
	if m == nil {
		m, err = New(emt.selector, "", V2)
		if err != nil {
			return nil, fmt.Errorf("cannot create macaroon: %v", err)
		}
	}
	for _, v := range emt.operations {
		err = m.AddFirstPartyCaveat(v)
		if err != nil {
			return nil, fmt.Errorf("cannot add first-party caveat: %v", err)
		}
	}
	for _, d := range emt.delegatedOps {
		err = m.AddCaveat(d.operation, d.verificationId, d.location)
		if err != nil {
			return nil, fmt.Errorf("cannot add third-party caveat: %v", err)
		}
	}
	err = m.Sign(emt.key, emt.signer)
	if err != nil {
		return nil, fmt.Errorf("cannot sign macaroon: %v", err)
	}
	marsh := Marshaller{Macaroon: *m}
	
	return &marsh, nil
}





