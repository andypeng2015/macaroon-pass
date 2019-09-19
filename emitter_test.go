package macaroon_pass

import (
	"gopkg.in/check.v1"
	"testing"
)

func Test(t *testing.T) {
	check.TestingT(t)
}

type TestSuite struct {
	Env Environment
}

var _ = check.Suite(&TestSuite{})

func (s *TestSuite) SetUpSuite(c *check.C) {
	var err error
	s.Env.Key, err = RandomKey(16)
	c.Assert(err, check.IsNil)

}

func (suite *TestSuite) TestEmitMacaroonOperations (c *check.C) {
	ops := []string {"123456789012", "payment"}

	macaroon, err := suite.Env.EmitMacaroon(ops)
	c.Assert(err, check.IsNil)

	strId := string(macaroon.Id())
	c.Assert(strId, check.Equals, "123456789012|payment")

}