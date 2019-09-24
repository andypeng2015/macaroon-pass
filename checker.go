package macaroon_pass

import (
	"bytes"
	"fmt"
	"github.com/ArrowPass/macaroon"
)

//type OperationsAuthorizer interface {
//	ExtractOperations(macaroonId []byte) []string
//}

type CaveatChecker interface {
	CheckCaveat(environment *Environment, caveat *macaroon.Caveat) error
}

type BaseChecker struct {
	Environment
	macaroons []macaroon.Macaroon
}

func NewBaseChecker(keyRequester func([]byte) []byte, macaroons []macaroon.Macaroon) (*BaseChecker, error) {
	if len(macaroons) < 1 {
		return nil, fmt.Errorf("No macaroons to check passed")
	}
	checker := BaseChecker {
		Environment:  Environment {
			Key:           keyRequester(macaroons[0].Id()),
		},
		macaroons:     macaroons,
	}
	
	return &checker, checker.authenticate()
}

func (ch *BaseChecker) authenticate () error {
	_, err := ch.macaroons[0].VerifySignature(ch.Key, nil)
	if err != nil {
		return fmt.Errorf("Macaroon authentication failed: %v", err)
	}
	return nil
}

func (ch *BaseChecker) Authorize (operation []byte) error {
	
	for _, cav := range ch.macaroons[0].Caveats() {
		if bytes.Compare(cav.Id, operation) == 0 {
			return nil
		}
	}
	
	return fmt.Errorf("Cannot authorize: %s", string(operation))
}


