package be

import (
	"btd/elgamal"
	"btd/prf"
	"bytes"
	"fmt"
	"go.dedis.ch/kyber/v4"
	"go.dedis.ch/kyber/v4/pairing"
	"math"
)

type CT struct {
	i      int
	gamma  kyber.Point
	kp     kyber.Point
	c      elgamal.CT
	mPad   kyber.Point
	cM     []byte
	m      []byte
	gammaR kyber.Point
	rPad   kyber.Point
	cK     []byte
	k      kyber.Scalar
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
	r := b.suite.GT().Scalar().Pick(b.suite.RandomStream())
	rPad := b.suite.GT().Point().Mul(r, nil)
	gammaR := b.suite.GT().Point().Add(pad, rPad)
	rPadBytes, err := rPad.MarshalBinary()
	if err != nil {
		return CT{}, err
	}
	seedR := b.suite.Hash().Sum(rPadBytes)
	kBytes, err := k.MarshalBinary()
	if err != nil {
		return CT{}, err
	}
	cK := make([]byte, len(kBytes))
	b.suite.XOF(seedR).XORKeyStream(cK, kBytes)
	return CT{
		i:      i,
		gamma:  gamma,
		kp:     kp,
		c:      egct,
		mPad:   MPad,
		cM:     cM,
		m:      m,
		gammaR: gammaR,
		rPad:   rPad,
		cK:     cK,
		k:      k,
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
		if !MPad.Equal(ct.mPad) {
			return count, fmt.Errorf("decryption failed on index %d, wrong mPad", ct.i)
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

func (b *BTD) BatchDecOpt(cts []CT, sk kyber.Scalar) ([]kyber.Point, error) {
	L := len(cts)
	if L > b.B {
		return nil, fmt.Errorf("too many ciphertexts for the given crs")
	}
	lgL := int(math.Ceil(math.Log2(float64(L))))
	Ks := make([]kyber.Point, lgL)
	var err error
	for l := 0; l < lgL; l++ {
		x := math.Pow(2, float64(l))
		start := int(math.Floor(float64(L) * (x - 1.0) / x))
		Ks[l], err = b.BatchDec(cts[start:], sk)
		if err != nil {
			return nil, err
		}
	}
	return Ks, nil
}

func (b *BTD) BatchCombineOpt(cts []CT, Ks []kyber.Point) (int, error) {
	count := 0
	L := len(cts)
	if L > b.B {
		return count, fmt.Errorf("too many ciphertexts for the given crs")
	}
	KsIdx := 1
	ks := make([]kyber.Scalar, L)
	for idx, ct := range cts {
		if idx != ct.i {
			return count, fmt.Errorf("decryption failed on index %d, wrong index", ct.i)
		}
		count++
		prfKi, err := b.prf.ExpEval(Ks[0], ct.i)
		if err != nil {
			return count, err
		}
		sum := b.suite.GT().Point().Null()
		x := math.Pow(2, float64(KsIdx))
		nextStart := int(math.Floor(float64(L) * (x - 1.0) / x))
		if idx >= nextStart {
			KsIdx++
		}
		if idx > 0 {
			kLower := b.prf.SumKeys(ks[:idx])
			eval, err := b.prf.Eval(kLower, ct.i)
			if err != nil {
				return count, err
			}
			sum = b.suite.GT().Point().Add(sum, eval)
		}
		for j := idx + 1; j < L; j++ {
			var eval kyber.Point
			if KsIdx < len(Ks) && j == nextStart {
				count++
				eval, err = b.prf.ExpEval(Ks[KsIdx], ct.i)
				if err != nil {
					return count, err
				}
				sum = b.suite.GT().Point().Add(sum, eval)
				break
			}
			count++
			eval, err = b.prf.PEval(cts[j].kp, cts[j].i, ct.i)
			if err != nil {
				return count, err
			}
			sum = b.suite.GT().Point().Add(sum, eval)

		}

		MPad := b.suite.GT().Point().Sub(b.suite.GT().Point().Add(ct.gamma, sum), prfKi)
		if !MPad.Equal(ct.mPad) {
			return count, fmt.Errorf("decryption failed on index %d, wrong mPad", ct.i)
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

		RPad := b.suite.GT().Point().Sub(b.suite.GT().Point().Add(ct.gammaR, sum), prfKi)
		if !RPad.Equal(ct.rPad) {
			return count, fmt.Errorf("decryption failed on index %d, wrong rPad", ct.i)
		}
		RPadBytes, err := RPad.MarshalBinary()
		if err != nil {
			return count, err
		}
		seedR := b.suite.Hash().Sum(RPadBytes)
		kBytes := make([]byte, len(ct.cK))
		b.suite.XOF(seedR).XORKeyStream(kBytes, ct.cK)
		k := b.suite.Scalar().Zero()
		err = k.UnmarshalBinary(kBytes)
		if err != nil {
			return count, err
		}
		if !k.Equal(ct.k) {
			return count, fmt.Errorf("decryption failed on index %d, wrong k", ct.i)
		}
		ks[idx] = k
		kpCheck, err := b.prf.Puncture(k, ct.i)
		if err != nil {
			return count, err
		}
		if !kpCheck.Equal(ct.kp) {
			return count, fmt.Errorf("decryption failed on index %d, wrong kp", ct.i)
		}
	}
	return count, nil
}
