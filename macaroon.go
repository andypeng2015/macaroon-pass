// The macaroon package implements macaroons as described in
// the paper "Macaroons: Cookies with Contextual Caveats for
// Decentralized Authorization in the Cloud"
// (http://theory.stanford.edu/~ataly/Papers/macaroons.pdf)
//
// See the macaroon bakery packages at http://godoc.org/gopkg.in/macaroon-bakery.v2
// for higher level services and operations that use macaroons.
package macaroon_pass

import (
	"bytes"
	"fmt"
	"unicode/utf8"
)

// Macaroon holds a macaroon.
// See Fig. 7 of http://theory.stanford.edu/~ataly/Papers/macaroons.pdf
// for a description of the data contained within.
// Macaroons are mutable objects - use Clone as appropriate
// to avoid unwanted mutation.
type Macaroon struct {
	location string
	id       []byte
	caveats  []Caveat
	sig      []byte
	version  Version
}

// Equal reports whether m has exactly the same content as m1.
func (m *Macaroon) Equal(m1 *Macaroon) bool {
	if m == m1 || m == nil || m1 == nil {
		return m == m1
	}
	if m.location != m1.location ||
		!bytes.Equal(m.id, m1.id) ||
		!bytes.Equal(m.sig, m1.sig) ||
		m.version != m1.version ||
		len(m.caveats) != len(m1.caveats) {
		return false
	}
	for i, c := range m.caveats {
		if !c.Equal(m1.caveats[i]) {
			return false
		}
	}
	return true
}

// Caveat holds a first party or third party caveat.
type Caveat struct {
	// Id holds the id of the caveat. For first
	// party caveats this holds the condition;
	// for third party caveats this holds the encrypted
	// third party caveat.
	Id []byte

	// VerificationId holds the verification id. If this is
	// non-empty, it's a third party caveat.
	VerificationId []byte

	// For third-party caveats, Location holds the
	// ocation hint. Note that this is not signature checked
	// as part of the caveat, so should only
	// be used as a hint.
	Location string
}

// Equal reports whether c is equal to c1.
func (c Caveat) Equal(c1 Caveat) bool {
	return bytes.Equal(c.Id, c1.Id) &&
		bytes.Equal(c.VerificationId, c1.VerificationId) &&
		c.Location == c1.Location
}

// isThirdParty reports whether the caveat must be satisfied
// by some third party (if not, it's a first person caveat).
func (cav *Caveat) IsThirdParty() bool {
	return len(cav.VerificationId) > 0
}

// New returns a new macaroon with the given root key,
// identifier, location and version.
func New(id []byte, loc string, version Version) (*Macaroon, error) {
	var m Macaroon
	if version < V2 {
		if !utf8.Valid(id) {
			return nil, fmt.Errorf("invalid id for %v macaroon", id)
		}
		// TODO check id length too.
	}
	if version < V1 || version > LatestVersion {
		return nil, fmt.Errorf("invalid version %v", version)
	}
	m.version = version
	m.init(append([]byte(nil), id...), loc, version)
	//derivedKey := MakeKey(rootKey)
	//m.sig = *HmacSha256KeyedHash(derivedKey, m.id)
	return &m, nil
}

// init initializes the macaroon. It retains a reference to id.
func (m *Macaroon) init(id []byte, loc string, vers Version) {
	m.location = loc
	m.id = append([]byte(nil), id...)
	m.version = vers
}

// SetLocation sets the location associated with the macaroon.
// Note that the location is not included in the macaroon's
// hash chain, so this does not change the signature.
func (m *Macaroon) SetLocation(loc string) {
	m.location = loc
}

// Clone returns a copy of the receiving macaroon.
func (m *Macaroon) Clone() *Macaroon {
	m1 := *m
	// Ensure that if any caveats are appended to the new
	// macaroon, it will copy the caveats.
	m1.caveats = m1.caveats[0:len(m1.caveats):len(m1.caveats)]
	return &m1
}

// Location returns the macaroon's location hint. This is
// not verified as part of the macaroon.
func (m *Macaroon) Location() string {
	return m.location
}

// Id returns the id of the macaroon. This can hold
// arbitrary information.
func (m *Macaroon) Id() []byte {
	return append([]byte(nil), m.id...)
}

// Signature returns the macaroon's signature.
func (m *Macaroon) Signature() []byte {
	// sig := m.sig
	// return sig[:]
	// Work around https://github.com/golang/go/issues/9537
	//sig := new([hashLen]byte)
	//*sig = m.sig
	return append([]byte(nil), m.sig...)
	
}

// Caveats returns the macaroon's caveats.
// This method will probably change, and it's important not to change the returned caveat.
func (m *Macaroon) Caveats() []Caveat {
	return m.caveats[0:len(m.caveats):len(m.caveats)]
}

func (m *Macaroon) GetCaveatById(cavId []byte) *Caveat {
	for _, cav := range m.caveats {
		if bytes.Equal(cav.Id, cavId) {
			return &cav
		}
	}
	return nil
}

// appendCaveat appends a caveat without modifying the macaroon's signature.
func (m *Macaroon) appendCaveat(caveatId, verificationId []byte, loc string) {
	if len(verificationId) == 0 {
		// Ensure that an empty vid is always represented by nil,
		// so that marshalers don't procuce spurious zero-length
		// vid fields which can confuse some verifiers.
		verificationId = nil
	}
	m.caveats = append(m.caveats, Caveat{
		Id:             caveatId,
		VerificationId: verificationId,
		Location:       loc,
	})
}

func (m *Macaroon) AddCaveat(caveatId, verificationId []byte, loc string) error {
	if m.version < V2 {
		if !utf8.Valid(caveatId) {
			return fmt.Errorf("invalid caveat id for %v macaroon", m.version)
		}
		// TODO check caveat length too.
	}

	cavIdCopy := make([]byte, len(caveatId))
	copy(cavIdCopy, caveatId)

	vIdCopy := make([]byte, len(verificationId))
	copy(vIdCopy, verificationId)

	locationBytes := []byte(loc)
	locationCopyBytes := make([]byte, len(locationBytes))
	copy(locationCopyBytes, locationBytes)

	m.appendCaveat(cavIdCopy, vIdCopy, string(locationCopyBytes))

	return nil
}

// Bind prepares the macaroon for being used to discharge the
// macaroon with the given signature sig. This must be
// used before it is used in the discharges argument to Verify.
func (m *Macaroon) Bind(sig []byte) {
	m.sig = bindForRequest(sig, m.sig)
}

// AddFirstPartyCaveat adds a caveat that will be verified
// by the target service.
func (m *Macaroon) AddFirstPartyCaveat(condition []byte) error {
	m.AddCaveat(condition, nil, "")
	return nil
}

// AddThirdPartyCaveat adds a third-party caveat to the macaroon,
// using the given shared root key, caveat id and location hint.
// The caveat id should encode the root key in some
// way, either by encrypting it with a key known to the third party
// or by holding a reference to it stored in the third party's
// storage.
//func (m *Macaroon) AddThirdPartyCaveat(rootKey, caveatId []byte, loc string) error {
//	return m.addThirdPartyCaveatWithRand(rootKey, caveatId, loc, rand.Reader)
//}
//
//// addThirdPartyCaveatWithRand adds a third-party caveat to the macaroon, using
//// the given source of randomness for encrypting the caveat id.
//func (m *Macaroon) addThirdPartyCaveatWithRand(rootKey, caveatId []byte, loc string, r io.Reader) error {
//	derivedKey := MakeKey(rootKey)
//	verificationId, err := encrypt(&m.sig, derivedKey, r)
//	if err != nil {
//		return err
//	}
//	m.AddCaveat(caveatId, verificationId, loc)
//	return nil
//}

var zeroKey [hashLen]byte

// bindForRequest binds the given macaroon
// to the given signature of its parent macaroon.
func bindForRequest(rootSig []byte, dischargeSig []byte) []byte {
	if bytes.Equal(rootSig, dischargeSig) {
		return dischargeSig
	}
	return keyedHash2(zeroKey[:], rootSig, dischargeSig[:])
}

// Verify verifies that the receiving macaroon is valid.
// The root key must be the same that the macaroon was originally
// minted with. The check function is called to verify each
// first-party caveat - it should return an error if the
// condition is not met.
//
// The discharge macaroons should be provided in discharges.
//
// Verify returns nil if the verification succeeds.
//func (m *Macaroon) Verify(rootKey []byte, check func(caveat string) error, discharges []*Macaroon) error {
//	var vctx verificationContext
//	vctx.init(rootKey, m, discharges, check)
//	return vctx.verify(m, rootKey)
//}

// VerifySignature verifies the signature of the given macaroon with respect
// to the root key, but it does not validate any first-party caveats. Instead
// it returns all the applicable first party caveats on success.
//
// The caller is responsible for checking the returned first party caveat
// conditions.
//func (m *Macaroon) VerifySignature(rootKey []byte, discharges []*Macaroon) ([]string, error) {
//	n := len(m.caveats)
//	for _, dm := range discharges {
//		n += len(dm.caveats)
//	}
//	conds := make([]string, 0, n)
//	var vctx verificationContext
//	vctx.init(rootKey, m, discharges, func(cond string) error {
//		conds = append(conds, cond)
//		return nil
//	})
//	err := vctx.verify(m, rootKey)
//	if err != nil {
//		return nil, err
//	}
//	return conds, nil
//}

// TraceVerify verifies the signature of the macaroon without checking
// any of the first party caveats, and returns a slice of Traces holding
// the operations used when verifying the macaroons.
//
// Each element in the returned slice corresponds to the
// operation for one of the argument macaroons, with m at index 0,
// and discharges at 1 onwards.
//func (m *Macaroon) TraceVerify(rootKey []byte, discharges []*Macaroon) ([]Trace, error) {
//	var vctx verificationContext
//	vctx.init(rootKey, m, discharges, func(string) error { return nil })
//	vctx.traces = make([]Trace, len(discharges)+1)
//	err := vctx.verify(m, rootKey)
//	return vctx.traces, err
//}

func (m *Macaroon) Sign(signer Signer) error {
	err := signer.SignMacaroon(m)
	if err != nil {
		return err
	}
	return nil
}

func (m *Macaroon) EraseSignature() {
	m.sig = nil
}

func (m *Macaroon) SetSignature(sig []byte) {
	newSig := make([]byte, len(sig))
	copy(newSig, sig)
	m.sig = newSig
}
