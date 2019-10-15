package macaroon_pass

import (
	"gopkg.in/check.v1"
)

type EmitterTestSuite struct {
	key []byte
	selector []byte
	operations [][]byte
}

var _ = check.Suite(&EmitterTestSuite{})

func (suite *EmitterTestSuite) SetUpSuite(c *check.C) {
	k, err := RandomKey(32)
	c.Assert(err, check.IsNil)
	
	suite.key = MakeKey(k)

	suite.selector = []byte("123456789012")
	suite.operations = [][]byte{[]byte("invoice12345678"), []byte("das0987654321")}
}

func (suite *EmitterTestSuite) TestEmitMacaroon (c *check.C) {
	signer, err := NewHmacSha256Signer(suite.key)
	c.Assert(err, check.IsNil)

	emitter := NewEmitter(&signer, suite.selector)

	m, err := emitter.EmitMacaroon()
	c.Assert(err, check.IsNil)

	c.Assert(m.Id(), check.DeepEquals, suite.selector)
}

func (suite *EmitterTestSuite)  TestEmitMacaroonOperations (c *check.C) {
	signer, err := NewHmacSha256Signer(suite.key)
	c.Assert(err, check.IsNil)

	emitter := NewEmitter(&signer, suite.selector)

	for _, op := range suite.operations {
		err := emitter.AuthorizeOperation(op)
		c.Assert(err, check.IsNil)
	}
	
	m, err := emitter.EmitMacaroon()
	c.Assert(err, check.IsNil)
	
	c.Assert(m.Id(), check.DeepEquals, suite.selector)
	for i, cav := range m.Caveats() {
		c.Assert(cav.Id, check.DeepEquals, suite.operations[i])
	}
	
}