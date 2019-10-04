package macaroon_pass

import (
	"bytes"
	"fmt"
	"github.com/ArrowPass/macaroon"
)

type Context interface {
	VerifySignature (macaroon *macaroon.Macaroon) error
	GetDischargeMacaroon (caveat *macaroon.Caveat) (*macaroon.Macaroon, error)
	ProcessOperation(op []byte) error
}

type Operation struct {
	Value      []byte
	Authorized bool
}

func VerifyMacaroon(macaroon *macaroon.Macaroon, context Context, rawOperations [][]byte) error {
	mOps, err := processMacaroon(macaroon, context)
	if err != nil {
		return fmt.Errorf("macaroon verification error: %v", err)
	}
	for _, rawOp := range rawOperations {
		found := false
		for i, _ := range mOps {
			if bytes.Equal(mOps[i].Value, rawOp) {
				found = true
				mOps[i].Authorized = true
				break
			}
		}
		if !found {
			return fmt.Errorf("macaroon verification error: %s" , string(rawOp))
		}
		
	}
	for _, op := range mOps {
		if !op.Authorized {
			err = context.ProcessOperation(op.Value)
			if err != nil {
				return fmt.Errorf("condition is not met %s: %v", string(op.Value), err)
			}
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
		operations = append(operations, Operation{Value: caveat.Id})
		if caveat.IsThirdParty() {
			dMacaroon, err := context.GetDischargeMacaroon(&caveat)
			if err == nil {
				err = context.VerifySignature(dMacaroon)
				if err != nil {
					return nil, err
				}
				var addOps []Operation
				addOps, err = processMacaroon(dMacaroon, context)
				if err != nil {
					return nil, err
				}
				operations = append(operations, addOps...)
			} else {
				return nil, err
			}
		}
	}
	return operations, nil
}

