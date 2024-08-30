package curves

import (
	"go.dedis.ch/kyber/v4"
	"go.dedis.ch/kyber/v4/pairing"
)

type Suite interface {
	pairing.Suite
	GTBase() kyber.Point
	PickGT() kyber.Point
}

type suite struct {
	pairing.Suite
	gtBase kyber.Point
}

func NewSuite(s pairing.Suite) Suite {
	gtBase := s.Pair(s.G1().Point().Base(), s.G2().Point().Base())
	return &suite{
		Suite:  s,
		gtBase: gtBase,
	}
}

func (s *suite) PickGT() kyber.Point {
	b := s.GTBase()
	return b.Mul(s.GT().Scalar().Pick(s.RandomStream()), b)
}

func (s *suite) GTBase() kyber.Point {
	return s.gtBase.Clone()
}
