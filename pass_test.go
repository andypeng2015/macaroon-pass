package macaroon_pass

import (
	"bytes"
	"encoding/hex"
	"fmt"
	"github.com/dcpn-io/threshold"
	"gopkg.in/check.v1"
	"testing"
)

func TestMacaroonPass(t *testing.T) {
	check.TestingT(t)
}

type PassTestSuite struct {
	key                []byte
	hmacSha256Selector []byte
	operations         [][]byte
	payOp              []byte
	
	ecdsaSelector      []byte
	priv               []byte
	pub                []byte
}

func (s *PassTestSuite) VerifySignature (m *Macaroon) error {
	if bytes.Equal(m.Id(), s.hmacSha256Selector) {
		return HmacSha256SignatureVerify(s.key, m)
	} else if bytes.Equal(m.Id(), s.ecdsaSelector) {
		return EcdsaSignatureVerify(s.pub, m)
	} else {
		return fmt.Errorf("wrong test macaroon selector")
	}
}

func (s *PassTestSuite) GetDischargeMacaroon (caveat *Caveat) (*Macaroon, error) {
	return nil, nil
}

func (s *PassTestSuite) ProcessOperation(op []byte) error {
	var err error
	if bytes.Equal(op, []byte("payment")) {
		err = nil
	} else {
		err = fmt.Errorf("unknown operation: %s", string(op))
	}
	return err
}

var _ = check.Suite(&PassTestSuite{})

func (s *PassTestSuite) SetUpSuite(c *check.C) {
	k, err := RandomKey(32)
	c.Assert(err, check.IsNil)

	s.key = MakeKey(k)
	s.hmacSha256Selector = []byte("HMAC Sha256")
	s.operations = [][]byte{[]byte("payment"), []byte("read")}
	s.payOp = []byte("payment")
	
	s.ecdsaSelector = []byte("ECDSA")
	priv, pub, _ := threshold.GenerateKeys()
	s.priv = priv.Serialize()
	s.pub = pub.Serialize()
}

func (s *PassTestSuite) TestAuthenticate(c *check.C) {
	signer, err := NewHmacSha256Signer(s.key)
	c.Assert(err, check.IsNil)

	emt := NewEmitter(signer, s.hmacSha256Selector)
	
	err = emt.AuthorizeOperation(s.operations[0])
	c.Assert(err, check.IsNil)

	err = emt.AuthorizeOperation(s.operations[1])
	c.Assert(err, check.IsNil)
	
	m, err := emt.EmitMacaroon()
	c.Assert(err, check.IsNil)

	buf, err := MarshalBinary(&MacaroonSlice{[]*Macaroon{m}})
	c.Assert(err, check.IsNil)

	unmarshalled, err := UnmarshalBinary(buf)
	c.Assert(err, check.IsNil)

	u, err := unmarshalled.Get(0)
	c.Assert(err, check.IsNil)

	err = VerifyMacaroon(u, s, s.operations)
	c.Assert(err, check.IsNil)
}

func (s *PassTestSuite) TestEcdsaSignaturePass (c *check.C) {
	signer := NewEcdsaSigner(s.priv)
	emt := NewEmitter(signer, s.ecdsaSelector)
	
	err := emt.AuthorizeOperation(s.operations[0])
	c.Assert(err, check.IsNil)
	err = emt.AuthorizeOperation(s.operations[1])
	c.Assert(err, check.IsNil)
	
	m, err := emt.EmitMacaroon()
	c.Assert(err, check.IsNil)

	buf, err := MarshalBinary(&MacaroonSlice{[]*Macaroon{m}})
	c.Assert(err, check.IsNil)
	
	u, err := UnmarshalBinary(buf)
	c.Assert(err, check.IsNil)

	um, err := u.Get(0)
	c.Assert(err, check.IsNil)

	err = VerifyMacaroon(um, s, s.operations)
	c.Assert(err, check.IsNil)
}

func (s *PassTestSuite) TestNilOperations(c *check.C) {
	signer, err := NewHmacSha256Signer(s.key)
	c.Assert(err, check.IsNil)

	emt := NewEmitter(signer, s.hmacSha256Selector)
	
	m, err := emt.EmitMacaroon()
	c.Assert(err, check.IsNil)

	buf, err := MarshalBinary(&MacaroonSlice{[]*Macaroon{m}})
	c.Assert(err, check.IsNil)

	u, err := UnmarshalBinary(buf)
	c.Assert(err, check.IsNil)

	um, err := u.Get(0)
	c.Assert(err, check.IsNil)

	err = VerifyMacaroon(um, s, nil)
	c.Assert(err, check.IsNil)
}

func (s *PassTestSuite) TestEmitterWithMacaroonBase(c *check.C) {
	signer, err := NewHmacSha256Signer(s.key)
	c.Assert(err, check.IsNil)

	emt := NewEmitter(signer, s.hmacSha256Selector)

	m, err := emt.EmitMacaroon()
	c.Assert(err, check.IsNil)

	buf, err := MarshalBinary(&MacaroonSlice{[]*Macaroon{m}})
	c.Assert(err, check.IsNil)

	u, err := UnmarshalBinary(buf)
	c.Assert(err, check.IsNil)

	um, err := u.Get(0)
	c.Assert(err, check.IsNil)

	var signer2 Signer
	signer2, err = DeriveHmacSha256Signer(um)
	c.Assert(err, check.IsNil)

	emt2 := RecreateEmitter(signer2, um)

	for _, op := range s.operations {
		err = emt2.AuthorizeOperation(op)
		c.Assert(err, check.IsNil)
	}

	m2, err := emt2.EmitMacaroon()
	c.Assert(err, check.IsNil)

	buf2, err := MarshalBinary(&MacaroonSlice{[]*Macaroon{m2}})
	c.Assert(err, check.IsNil)

	u2, err := UnmarshalBinary(buf2)
	c.Assert(err, check.IsNil)

	um2, err := u2.Get(0)
	c.Assert(err, check.IsNil)

	err = VerifyMacaroon(um2, s, s.operations)
	c.Assert(err, check.IsNil)
}

func (s *PassTestSuite) TestPassWithEcdsa(c *check.C) {
	signer := NewEcdsaSigner(s.priv)

	emt := NewEmitter(signer, s.ecdsaSelector)

	err := emt.AuthorizeOperation([]byte("das " + "DAS ID"))
	c.Assert(err, check.IsNil)

	m, err := emt.EmitMacaroon()
	c.Assert(err, check.IsNil)

	macaroonSlice := &MacaroonSlice{}
	macaroonSlice.Add(m)

	mcrn, err := macaroonSlice.Get(0)

	c.Assert(err, check.IsNil)
	c.Logf("Macaroon: Macaroon: ID: " + string(mcrn.Id()))
	c.Logf("Macaroon: Macaroon: Sign: " + hex.EncodeToString(mcrn.Signature()))

	for i, caveat := range mcrn.Caveats() {
		c.Logf("  Caveat %v ID: " + string(caveat.Id), i)
		c.Logf("  Caveat %v VerificationId: " + string(caveat.VerificationId), i)
		c.Logf("  Caveat %v Location: " + caveat.Location, i)
	}

	data, err := MarshalBinary(macaroonSlice)
	c.Assert(err, check.IsNil)

	unmarshalled, err := UnmarshalBinary(data)
	c.Assert(err, check.IsNil)

	mcrn1, err := unmarshalled.Get(0)
	c.Assert(err, check.IsNil)

	c.Logf("Unmarshalled: Macaroon: ID: " + string(mcrn1.Id()))
	c.Logf("Unmarshalled: Macaroon: Sign: " + hex.EncodeToString(mcrn1.Signature()))

	c.Assert(mcrn1.Id(), check.DeepEquals, mcrn.Id())
	c.Assert(mcrn1.Signature(), check.DeepEquals, mcrn.Signature())

	for i, caveat1 := range mcrn1.Caveats() {
		c.Logf("  Caveat %v ID: " + string(caveat1.Id), i)
		c.Logf("  Caveat %v VerificationId: " + string(caveat1.VerificationId), i)
		c.Logf("  Caveat %v Location: " + caveat1.Location, i)

		caveat := mcrn.Caveats()[i]

		c.Assert(caveat1.Id, check.DeepEquals, caveat.Id)
		c.Assert(caveat1.VerificationId, check.DeepEquals, caveat.VerificationId)
		c.Assert(caveat1.Location, check.DeepEquals, caveat.Location)
	}

	err = VerifyMacaroon(mcrn1, s, [][]byte {[]byte("das " + "DAS ID")})
	c.Assert(err, check.IsNil)
}