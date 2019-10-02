package macaroon_pass

import (
	"bytes"
	"fmt"
	"github.com/ArrowPass/macaroon"
)

type Context interface {
	VerifySignature (macaroon *macaroon.Macaroon) error
	GetDischargeMacaroon (caveat *macaroon.Caveat) (*macaroon.Macaroon, error)
}

type Operation struct {
	op []byte
	authorized bool
}

func VerifyMacaroon(macaroon *macaroon.Macaroon, context Context, rawOperations [][]byte) error {
	mOps, err := processMacaroon(macaroon, context)
	if err != nil {
		return fmt.Errorf("macaroon verification error: %v", err)
	}
	for _, rawOp := range rawOperations {
		found := false
		for _, op := range mOps {
			if bytes.Equal(op.op, rawOp) {
				found = true
			}
		}
		if !found {
			return fmt.Errorf("macaroon verification error")
		}
		
	}
	return nil
}

func processMacaroon(macaroon *macaroon.Macaroon, context Context) ([]Operation, error) {
	err := context.VerifySignature(macaroon)
	if err != nil {
		return nil, err
	}
	
	var operations []Operation
	
	for _, caveat := range macaroon.Caveats() {
		operations = append(operations, Operation{op:caveat.Id})
		if caveat.IsThirdParty() {
			dMacaroon, err := context.GetDischargeMacaroon(&caveat)
			if err == nil {
				err = context.VerifySignature(dMacaroon)
				if err == nil {
					addOps, err := processMacaroon(dMacaroon, context)
					if err == nil {
						operations[len(operations)-1].authorized = true
					}
					operations = append(operations, addOps...)
				}
			}
			
		} else {
			operations[len(operations)-1].authorized = true
		}
	}
	return operations, err
}

