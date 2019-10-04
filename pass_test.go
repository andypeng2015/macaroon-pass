package macaroon_pass

import (
	"bytes"
	"fmt"
	"github.com/ArrowPass/macaroon"
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

func (s *PassTestSuite) VerifySignature (m *macaroon.Macaroon) error {
	if bytes.Equal(m.Id(), s.hmacSha256Selector) {
		return macaroon.HmacSha256SignatureVerify(s.key, m)
	} else if bytes.Equal(m.Id(), s.ecdsaSelector) {
		return EcdsaSignatureVerify(s.pub, m)
	} else {
		return fmt.Errorf("wrong test macaroon selector")
	}
}

func (s *PassTestSuite) GetDischargeMacaroon (caveat *macaroon.Caveat) (*macaroon.Macaroon, error) {
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

	s.key = macaroon.MakeKey(k)
	s.hmacSha256Selector = []byte("HMAC Sha256")
	s.operations = [][]byte{[]byte("payment"), []byte("read")}
	s.payOp = []byte("payment")
	
	s.ecdsaSelector = []byte("ECDSA")
	priv, pub, _ := threshold.GenerateKeys()
	s.priv = priv.Serialize()
	s.pub = pub.Serialize()
}

func (s *PassTestSuite) TestAuthenticate(c *check.C) {
	
	emt := NewEmitter(s.key, macaroon.HmacSha256Signer, s.hmacSha256Selector)
	
	err := emt.AuthorizeOperation(s.operations[0])
	c.Assert(err, check.IsNil)
	err = emt.AuthorizeOperation(s.operations[1])
	c.Assert(err, check.IsNil)
	
	m, err := emt.EmitMacaroon()
	c.Assert(err, check.IsNil)

	buf, err := m.MarshalBinary()
	c.Assert(err, check.IsNil)

	var u macaroon.Marshaller
	err = u.UnmarshalBinary(buf)
	c.Assert(err, check.IsNil)

	err = VerifyMacaroon(&u.Macaroon, s, s.operations)
	c.Assert(err, check.IsNil)
	
}

func (s *PassTestSuite) TestEcdsaSignaturePass (c *check.C) {
	emt := NewEmitter(s.priv, EcdsaSigner, s.ecdsaSelector)
	
	err := emt.AuthorizeOperation(s.operations[0])
	c.Assert(err, check.IsNil)
	err = emt.AuthorizeOperation(s.operations[1])
	c.Assert(err, check.IsNil)
	
	m, err := emt.EmitMacaroon()
	c.Assert(err, check.IsNil)
	
	buf, err := m.MarshalBinary()
	c.Assert(err, check.IsNil)
	
	var u macaroon.Marshaller
	err = u.UnmarshalBinary(buf)
	c.Assert(err, check.IsNil)
	
	err = VerifyMacaroon(&u.Macaroon, s, s.operations)
	c.Assert(err, check.IsNil)
}

func (s *PassTestSuite) TestNilOperations(c *check.C) {
	
	emt := NewEmitter(s.key, macaroon.HmacSha256Signer, s.hmacSha256Selector)
	
	m, err := emt.EmitMacaroon()
	c.Assert(err, check.IsNil)
	
	buf, err := m.MarshalBinary()
	c.Assert(err, check.IsNil)
	
	var u macaroon.Marshaller
	err = u.UnmarshalBinary(buf)
	c.Assert(err, check.IsNil)
	
	err = VerifyMacaroon(&u.Macaroon, s, nil)
	c.Assert(err, check.IsNil)
	
}
