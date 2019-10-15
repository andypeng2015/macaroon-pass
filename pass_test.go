package macaroon_pass

import (
	"bytes"
	"fmt"
	"github.com/lcpo/threshold"
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

	emt := NewEmitter(&signer, s.hmacSha256Selector)
	
	err = emt.AuthorizeOperation(s.operations[0])
	c.Assert(err, check.IsNil)

	err = emt.AuthorizeOperation(s.operations[1])
	c.Assert(err, check.IsNil)
	
	m, err := emt.EmitMacaroon()
	c.Assert(err, check.IsNil)

	buf, err := MarshalBinary(MacaroonSlice{[]*Macaroon{m}})
	c.Assert(err, check.IsNil)

	unmarshalled, err := UnmarshalBinary(buf)
	c.Assert(err, check.IsNil)

	u, err := unmarshalled.get(0)
	c.Assert(err, check.IsNil)

	err = VerifyMacaroon(u, s, s.operations)
	c.Assert(err, check.IsNil)
}

func (s *PassTestSuite) TestEcdsaSignaturePass (c *check.C) {
	signer := NewEcdsaSigner(s.priv)
	emt := NewEmitter(&signer, s.ecdsaSelector)
	
	err := emt.AuthorizeOperation(s.operations[0])
	c.Assert(err, check.IsNil)
	err = emt.AuthorizeOperation(s.operations[1])
	c.Assert(err, check.IsNil)
	
	m, err := emt.EmitMacaroon()
	c.Assert(err, check.IsNil)

	buf, err := MarshalBinary(MacaroonSlice{[]*Macaroon{m}})
	c.Assert(err, check.IsNil)
	
	u, err := UnmarshalBinary(buf)
	c.Assert(err, check.IsNil)

	um, err := u.get(0)
	c.Assert(err, check.IsNil)

	err = VerifyMacaroon(um, s, s.operations)
	c.Assert(err, check.IsNil)
}

func (s *PassTestSuite) TestNilOperations(c *check.C) {

	signer, err := NewHmacSha256Signer(s.key)
	c.Assert(err, check.IsNil)

	emt := NewEmitter(&signer, s.hmacSha256Selector)
	
	m, err := emt.EmitMacaroon()
	c.Assert(err, check.IsNil)

	buf, err := MarshalBinary(MacaroonSlice{[]*Macaroon{m}})
	c.Assert(err, check.IsNil)

	u, err := UnmarshalBinary(buf)
	c.Assert(err, check.IsNil)

	um, err := u.get(0)
	c.Assert(err, check.IsNil)

	err = VerifyMacaroon(um, s, nil)
	c.Assert(err, check.IsNil)
	
}

func (s *PassTestSuite) TestEmitterWithMacaroonBase(c *check.C) {
	signer, err := NewHmacSha256Signer(s.key)
	c.Assert(err, check.IsNil)

	emt := NewEmitter(&signer, s.hmacSha256Selector)

	m, err := emt.EmitMacaroon()
	c.Assert(err, check.IsNil)

	buf, err := MarshalBinary(MacaroonSlice{[]*Macaroon{m}})
	c.Assert(err, check.IsNil)

	u, err := UnmarshalBinary(buf)
	c.Assert(err, check.IsNil)

	um, err := u.get(0)
	c.Assert(err, check.IsNil)

	signer2, err := DeriveHmacSha256Signer(um)
	emt2 := RecreateEmitter(&signer2, um)

	for _, op := range s.operations {
		emt2.AuthorizeOperation(op)
	}

	m2, err := emt2.EmitMacaroon()
	c.Assert(err, check.IsNil)

	buf2, err := MarshalBinary(MacaroonSlice{[]*Macaroon{m2}})
	c.Assert(err, check.IsNil)

	u2, err := UnmarshalBinary(buf2)
	c.Assert(err, check.IsNil)

	um2, err := u2.get(0)
	c.Assert(err, check.IsNil)

	err = VerifyMacaroon(um2, s, s.operations)
	c.Assert(err, check.IsNil)
}
