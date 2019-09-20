package macaroon_pass

import (
	"gopkg.in/check.v1"
)

type CheckerTestSuite struct {
	Env Environment
}

var _ = check.Suite(&CheckerTestSuite{})

func (s *CheckerTestSuite) SetUpSuite(c *check.C) {
	var err error
	s.Env.Key, err = RandomKey(16)
	c.Assert(err, check.IsNil)

}
