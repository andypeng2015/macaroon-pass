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
	var err error
	suite.key, err = RandomKey(16)
	c.Assert(err, check.IsNil)

	suite.selector = []byte("123456789012")
	suite.operations = [][]byte{[]byte("test1"), []byte("test2")}
}

func (suite *EmitterTestSuite) TestEmitMacaroon (c *check.C) {
	emitter := NewEmitter(suite.key, suite.selector)

	macaroon, err := emitter.EmitMacaroon()
	c.Assert(err, check.IsNil)

	c.Assert(macaroon.Id(), check.DeepEquals, suite.selector)
}

func (suite *EmitterTestSuite)  TestEmitMacaroonOperations (c *check.C) {
	emitter := NewEmitter(suite.key, suite.selector)
	emitter.DeclareOperations(suite.operations)
	
	macaroon, err := emitter.EmitMacaroon()
	c.Assert(err, check.IsNil)
	
	c.Assert(macaroon.Id(), check.DeepEquals, suite.selector)
	for i, cav := range macaroon.Caveats() {
		c.Assert(cav.Id, check.DeepEquals, suite.operations[i])
	}
	
}