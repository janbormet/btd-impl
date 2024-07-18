package be

import (
	"btd/elgamal"
	"btd/prf"
	"bytes"
	"fmt"
	"go.dedis.ch/kyber/v4"
	"go.dedis.ch/kyber/v4/pairing"
)

type CT struct {
	i     int
	gamma kyber.Point
	kp    kyber.Point
	c     elgamal.CT
	MPad  kyber.Point
	cM    []byte
	m     []byte
}

type BTD struct {
	suite *pairing.SuiteBn256
	prf   *prf.PRF
	eg    *elgamal.ElGamal
	B     int
}

func NewBTD(suite *pairing.SuiteBn256, B int) *BTD {
	prf := prf.PRFSetup(suite, B)
	eg := elgamal.NewElGamal(suite.G2(), suite.RandomStream())
	return &BTD{
		suite: suite,
		prf:   prf,
		eg:    eg,
		B:     B,
	}
}

func (b *BTD) KeyGen() (kyber.Scalar, kyber.Point) {
	return b.eg.KeyGen()
}

func (b *BTD) Enc(pk kyber.Point, i int, m []byte) (CT, error) {
	MPad := b.suite.GT().Point().Pick(b.suite.RandomStream())
	MPadBytes, err := MPad.MarshalBinary()
	if err != nil {
		return CT{}, err
	}
	k := b.prf.KeyGen()
	kp, err := b.prf.Puncture(k, i)
	if err != nil {
		return CT{}, err
	}
	K := b.suite.G2().Point().Mul(k, nil)
	egct := b.eg.Enc(pk, K)
	pad, err := b.prf.Eval(k, i)
	if err != nil {
		return CT{}, err
	}
	gamma := b.suite.GT().Point().Add(pad, MPad)
	seed := b.suite.Hash().Sum(MPadBytes)
	cM := make([]byte, len(m))
	b.suite.XOF(seed).XORKeyStream(cM, m)
	return CT{
		i:     i,
		gamma: gamma,
		kp:    kp,
		c:     egct,
		MPad:  MPad,
		cM:    cM,
		m:     m,
	}, nil
}

func (b *BTD) BatchDec(cts []CT, sk kyber.Scalar) (kyber.Point, error) {
	if len(cts) > b.B {
		return nil, fmt.Errorf("too many ciphertexts for the given crs")
	}
	sum := b.eg.NullEGct()
	for _, ct := range cts {
		sum = b.eg.AddCT(sum, ct.c)
	}
	return b.eg.Dec(sk, sum)
}

func (b *BTD) BatchCombine(cts []CT, K kyber.Point) (int, error) {
	count := 0
	if len(cts) > b.B {
		return count, fmt.Errorf("too many ciphertexts for the given crs")
	}
	for _, ct := range cts {
		count++
		prfKi, err := b.prf.ExpEval(K, ct.i)
		if err != nil {
			return count, err
		}
		sum := b.suite.GT().Point().Null()
		for j := 0; j < b.B; j++ {
			if j == ct.i {
				continue
			}
			count++
			peval, err := b.prf.PEval(cts[j].kp, cts[j].i, ct.i)
			if err != nil {
				return count, err
			}
			sum = b.suite.GT().Point().Add(sum, peval)
		}
		MPad := b.suite.GT().Point().Sub(b.suite.GT().Point().Add(ct.gamma, sum), prfKi)
		if !MPad.Equal(ct.MPad) {
			return count, fmt.Errorf("decryption failed on index %d, wrong MPad", ct.i)
		}
		MPadBytes, err := MPad.MarshalBinary()
		if err != nil {
			return count, err
		}
		seed := b.suite.Hash().Sum(MPadBytes)
		m := make([]byte, len(ct.cM))
		b.suite.XOF(seed).XORKeyStream(m, ct.cM)
		if !bytes.Equal(m, ct.m) {
			return count, fmt.Errorf("decryption failed on index %d", ct.i)
		}
	}
	return count, nil
}
