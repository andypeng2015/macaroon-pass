package macaroon_pass

import (
	"github.com/ArrowPass/macaroon"
	"gopkg.in/check.v1"
	"testing"
)

func TestMacaroonPass(t *testing.T) {
	check.TestingT(t)
}

type PassTestSuite struct {
	key []byte
	selector []byte
	operations [][]byte
	payOp []byte
}

var _ = check.Suite(&PassTestSuite{})

func (suite *PassTestSuite) SetUpSuite(c *check.C) {
	k, err := RandomKey(32)
	c.Assert(err, check.IsNil)

	suite.key = macaroon.MakeKey(k)
	suite.selector = []byte("123456789012")
	suite.operations = [][]byte{[]byte("payment"), []byte("read")}
	suite.payOp = []byte("payment")
}

func (suite *PassTestSuite) TestAuthenticate(c *check.C) {
	
	emt := NewEmitter(suite.key, macaroon.HmacSha256Signer, suite.selector)
	
	err := emt.AuthorizeOperation(suite.operations[0])
	c.Assert(err, check.IsNil)
	err = emt.AuthorizeOperation(suite.operations[1])
	c.Assert(err, check.IsNil)
	
	m, err := emt.EmitMacaroon()
	c.Assert(err, check.IsNil)

	buf, err := m.MarshalBinary()
	c.Assert(err, check.IsNil)

	var u macaroon.Marshaller
	err = u.UnmarshalBinary(buf)
	c.Assert(err, check.IsNil)

	//ch, err := NewBaseChecker(func(selector []byte) []byte {
	//	c.Assert(selector, check.DeepEquals, suite.selector)
	//	return suite.key
	//}, u[:])
	//c.Assert(err, check.IsNil)
	
	//err = ch.Authorize(suite.payOp)
	//c.Assert(err, check.IsNil)
	
}

