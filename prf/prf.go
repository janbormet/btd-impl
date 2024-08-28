package prf

import (
	"fmt"
	"go.dedis.ch/kyber/v4"
	"go.dedis.ch/kyber/v4/pairing"
)

type mkey struct {
	i int
	j int
}

type PRF struct {
	xi     []kyber.Scalar
	zi     []kyber.Scalar
	g2zi   []kyber.Point
	gTzi   []kyber.Point
	G1xi   []kyber.Point
	g2zixj map[mkey]kyber.Point
	B      int
	suite  *pairing.SuiteBn256
}

func PRFSetup(suite *pairing.SuiteBn256, B int) *PRF {
	setup := &PRF{
		xi:     make([]kyber.Scalar, B),
		zi:     make([]kyber.Scalar, B),
		g2zi:   make([]kyber.Point, B),
		gTzi:   make([]kyber.Point, B),
		G1xi:   make([]kyber.Point, B),
		g2zixj: make(map[mkey]kyber.Point),
		B:      B,
		suite:  suite,
	}
	for i := 0; i < B; i++ {
		setup.xi[i] = suite.G1().Scalar().Pick(suite.RandomStream())
		setup.zi[i] = suite.G2().Scalar().Pick(suite.RandomStream())
		setup.G1xi[i] = suite.G1().Point().Mul(setup.xi[i], nil)
		setup.g2zi[i] = suite.G2().Point().Mul(setup.zi[i], nil)
		setup.gTzi[i] = suite.GT().Point().Mul(setup.zi[i], nil)
	}
	for i := 0; i < B; i++ {
		for j := 0; j < B; j++ {
			setup.g2zixj[mkey{
				i: i,
				j: j,
			}] = suite.G2().Point().Mul(suite.Scalar().Div(setup.zi[i], setup.xi[j]), nil)
		}
	}
	return setup
}

func (f *PRF) KeyGen() kyber.Scalar {
	return f.suite.Scalar().Pick(f.suite.RandomStream())
}

func (f *PRF) SumKeys(k []kyber.Scalar) kyber.Scalar {
	sum := f.suite.Scalar().Zero()
	for _, ki := range k {
		sum = sum.Add(sum, ki)
	}
	return sum
}

func (f *PRF) Puncture(k kyber.Scalar, i int) (kyber.Point, error) {
	if i < 0 || i >= f.B {
		return nil, fmt.Errorf("puncturing index out of domain. Domain: [0, %d-1], index: %d", f.B, i)
	}
	return f.suite.G1().Point().Mul(k, f.G1xi[i]), nil
}

func (f *PRF) Eval(k kyber.Scalar, i int) (kyber.Point, error) {
	if i < 0 || i >= f.B {
		return nil, fmt.Errorf("evaluation index out of domain. Domain: [0, %d-1], index: %d", f.B, i)
	}
	return f.suite.GT().Point().Mul(k, f.gTzi[i]), nil
}

func (f *PRF) PEval(kp kyber.Point, pi, i int) (kyber.Point, error) {
	if i < 0 || i >= f.B {
		return nil, fmt.Errorf("punctured evaluation index out of domain. Domain: [0, %d-1], index: %d", f.B, i)
	}
	if pi < 0 || pi >= f.B {
		return nil, fmt.Errorf("punctured index out of domain for peval. Domain: [0, %d-1], index: %d", f.B, pi)
	}
	if pi == i {
		return nil, fmt.Errorf("punctured index cannot be the same as the evaluation index")
	}
	crselem := f.g2zixj[mkey{
		i: i,
		j: pi,
	}]
	return f.suite.Pair(kp, crselem), nil
}

func (f *PRF) ExpEval(K kyber.Point, i int) (kyber.Point, error) {
	if i < 0 || i >= f.B {
		return nil, fmt.Errorf("exponential evaluation index out of domain. Domain: [0, %d-1], index: %d", f.B, i)
	}
	return f.suite.Pair(K, f.g2zi[i]), nil
}
