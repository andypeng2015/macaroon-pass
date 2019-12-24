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

	cardKey []byte
	cardId []byte
	random []byte
	vID      []byte
	payCavId []byte
	dasCavId []byte
	amountCavId []byte

	baseSignature []byte
	resultSignature []byte

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

	s.cardKey,_ = hex.DecodeString("7f2b5755de2b52f3e843d2ba15c42f948e806a18c73b450e88258f5f45c0ffdc")
	s.cardId,_ = hex.DecodeString("3030303030303030303030303030303030303030303033334130383130303034")
	s.random,_ = hex.DecodeString("40C1750299AF1C704B46B96342294480DEC6DBEFCFA481FF8EB29F5431C3384918409BD18AE87FB51AFBDB5F99E39EB690975C36E07E12F99D099DBC0F8E7401")
	s.payCavId = []byte("payment lntb120u1pw7fh3spp5j5d27q84eykgz6l9lj86gpu9fpnnn7qp6d3ux24vufgjjrrpd6dsdp9g9e8ymmh2pshxueqw3jhxapqwp6hycmgv9ek2cqzpgxqzfvuh99cjcz74wpnlne4w788fsjx0m9jgv365u9hem7fzrrtf2uluprnfvwnlt5pqjw9dlfd8azr8g7wdxtwg09td32008ah53axkcp77gq9pc768")
	s.dasCavId = []byte("DAS 9FD91A9251A1D8FE55A0FDE4A87090D98E91CA0F58517F6FB2892836884B36F9")
	s.amountCavId = []byte("amount 12000")

	s.baseSignature,_ = hex.DecodeString("4AF05451CD8B86E8740B3AFD384B92076FF3DE68E2570EF9BD2CE4F9E290AB8B")
	s.resultSignature,_ = hex.DecodeString("560f809f6e989435eca2ed0ac2f563d5d6edbb1e58b1d10321dc98b82a8c53ec")

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

func (s *PassTestSuite) TestPassSeparateSignature(c *check.C) {
	signer, err := NewHmacSha256Signer(s.key)
	c.Assert(err, check.IsNil)

	emt := NewEmitter(signer, s.hmacSha256Selector)

	err = emt.AuthorizeOperation([]byte("das " + "DAS_ID"))
	c.Assert(err, check.IsNil)

	m, err := emt.EmitMacaroon()
	c.Assert(err, check.IsNil)

	sig := m.Signature()
	c.Assert(sig, check.NotNil)

	m.EraseSignature()
	c.Assert(m.Signature(), check.IsNil)

	macaroonSlice := &MacaroonSlice{}
	macaroonSlice.Add(m)

	data, err := MarshalBinary(macaroonSlice)
	c.Assert(err, check.IsNil)

	unmarshalled, err := UnmarshalBinary(data)
	c.Assert(err, check.IsNil)

	m1, err := unmarshalled.Get(0)
	c.Assert(err, check.IsNil)

	c.Logf("Unmarshalled: Macaroon: ID: " + string(m1.Id()))
	c.Assert(m1.Id(), check.DeepEquals, m.Id())

	m1.SetSignature(sig)

	c.Logf("Unmarshalled: Macaroon: Sign: " + hex.EncodeToString(m1.Signature()))
	c.Assert(m1.Signature(), check.DeepEquals, sig)

	for i, caveat1 := range m1.Caveats() {
		c.Logf("  Caveat %v ID: " + string(caveat1.Id), i)
		c.Logf("  Caveat %v VerificationId: " + string(caveat1.VerificationId), i)
		c.Logf("  Caveat %v Location: " + caveat1.Location, i)

		caveat := m.Caveats()[i]

		c.Assert(caveat1.Id, check.DeepEquals, caveat.Id)
		c.Assert(caveat1.VerificationId, check.DeepEquals, caveat.VerificationId)
		c.Assert(caveat1.Location, check.DeepEquals, caveat.Location)
	}

	err = VerifyMacaroon(m1, s, [][]byte {[]byte("das " + "DAS_ID")})
	c.Assert(err, check.IsNil)
}


func (s *PassTestSuite) TestHmacSha256MacaroonSignature (c *check.C) {

	signer,_ := NewHmacSha256Signer(s.cardKey)

	m,_ := New(s.cardId, "", V2)

	slice := MacaroonSlice{macaroons: []*Macaroon{m}}
	data, err := MarshalBinary(&slice)
	c.Assert(err, check.IsNil)

	c.Log("macaroon base: " + hex.EncodeToString(data))

	m.SetSignature(s.baseSignature)

	err = HmacSha256SignatureVerify(s.cardKey, m)
	c.Assert(err, check.IsNil)

	_ = m.AddFirstPartyCaveat(s.payCavId)
	//_ = m.AddFirstPartyCaveat(s.amountCavId)

	err = m.Sign(signer)
	c.Assert(err, check.IsNil)

	vId := HmacSha256KeyedHash(m.Signature(), s.random)
	c.Log("Verification ID: " + hex.EncodeToString(vId))

	_ = m.AddCaveat(s.dasCavId, vId, "das")

	signatures,_ := makeHmacSha256Signature(s.cardKey, m, 2)

	for _, sig := range signatures {
		c.Log("signature: " + hex.EncodeToString(sig))
	}

	c.Assert(signatures[len(signatures) - 1], check.DeepEquals, s.resultSignature)
}
