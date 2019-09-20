package macaroon_pass

import (
	"gopkg.in/check.v1"
	"gopkg.in/macaroon.v2"
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
	var err error
	suite.key, err = RandomKey(16)
	c.Assert(err, check.IsNil)

	suite.selector = []byte("123456789012")
	suite.operations = [][]byte{[]byte("payment"), []byte("read")}
	suite.payOp = []byte("payment")
}

func (suite *PassTestSuite) TestAuthenticate(c *check.C) {
	
	emt := NewEmitter(suite.key, suite.selector)
	emt.DeclareOperations(suite.operations)
	
	m, err := emt.EmitMacaroon()
	c.Assert(err, check.IsNil)

	buf, err := m.MarshalBinary()
	c.Assert(err, check.IsNil)

	u := [...]macaroon.Macaroon {{}}
	err = u[0].UnmarshalBinary(buf)
	c.Assert(err, check.IsNil)

	ch, err := NewBaseChecker(func(selector []byte) []byte {
		c.Assert(selector, check.DeepEquals, suite.selector)
		return suite.key
	}, u[:])
	c.Assert(err, check.IsNil)
	
	err = ch.Authorize(suite.payOp)
	c.Assert(err, check.IsNil)
	
}

