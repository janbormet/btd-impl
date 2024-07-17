package main

import (
	"bytes"
	"fmt"
	"go.dedis.ch/kyber/v4"
	"go.dedis.ch/kyber/v4/pairing"
	"go.dedis.ch/kyber/v4/util/random"
)

type EGct struct {
	A kyber.Point
	B kyber.Point
	m kyber.Point
}

func NullEGct(gr kyber.Group) EGct {
	return EGct{
		A: gr.Point().Null(),
		B: gr.Point().Null(),
		m: gr.Point().Null(),
	}
}

func (c EGct) Add(gr kyber.Group, other EGct) EGct {
	return EGct{
		A: gr.Point().Add(c.A, other.A),
		B: gr.Point().Add(c.B, other.B),
		m: gr.Point().Add(c.m, other.m),
	}
}

func ElGamalEncrypt(group kyber.Group, pubkey kyber.Point, m kyber.Point) EGct {

	// ElGamal-encrypt the point to produce ciphertext (K,C).
	k := group.Scalar().Pick(random.New()) // ephemeral private key
	A := group.Point().Mul(k, nil)         // ephemeral DH public key
	S := group.Point().Mul(k, pubkey)      // ephemeral DH shared secret
	B := S.Add(S, m)                       // message blinded with secret
	return EGct{
		A: A,
		B: B,
		m: m,
	}
}

func ElGamalDecrypt(group kyber.Group, prikey kyber.Scalar, c EGct) (
	message kyber.Point, err error) {

	S := group.Point().Mul(prikey, c.A)
	message = group.Point().Sub(c.B, S)
	if !c.m.Equal(message) {
		return nil, fmt.Errorf("elgamal decryption failed")
	}
	return message, nil
}

type mkey struct {
	i int
	j int
}

type Setup struct {
	xi     []kyber.Scalar
	zi     []kyber.Scalar
	g1zi   []kyber.Point
	gTzi   []kyber.Point
	g2xi   []kyber.Point
	g1zixj map[mkey]kyber.Point
	B      int
}

func PRFSetup(suite *pairing.SuiteBn256, B int) *Setup {
	setup := &Setup{
		xi:     make([]kyber.Scalar, B),
		zi:     make([]kyber.Scalar, B),
		g1zi:   make([]kyber.Point, B),
		gTzi:   make([]kyber.Point, B),
		g2xi:   make([]kyber.Point, B),
		g1zixj: make(map[mkey]kyber.Point),
		B:      B,
	}
	for i := 0; i < B; i++ {
		setup.xi[i] = suite.G2().Scalar().Pick(suite.RandomStream())
		setup.zi[i] = suite.G1().Scalar().Pick(suite.RandomStream())
		setup.g2xi[i] = suite.G2().Point().Mul(setup.xi[i], nil)
		setup.g1zi[i] = suite.G1().Point().Mul(setup.zi[i], nil)
		setup.gTzi[i] = suite.GT().Point().Mul(setup.zi[i], nil)
	}
	for i := 0; i < B; i++ {
		for j := 0; j < B; j++ {
			setup.g1zixj[mkey{
				i: i,
				j: j,
			}] = suite.G1().Point().Mul(suite.Scalar().Div(setup.zi[i], setup.xi[j]), nil)
		}
	}
	return setup
}

func PRFKeyGen(crs *Setup, suite *pairing.SuiteBn256) kyber.Scalar {
	return suite.Scalar().Pick(suite.RandomStream())
}

func PRFPuncture(crs *Setup, suite *pairing.SuiteBn256, k kyber.Scalar, i int) (kyber.Point, error) {
	if i < 0 || i >= crs.B {
		return nil, fmt.Errorf("puncturing index out of domain. Domain: [0, %d-1], index: %d", crs.B, i)
	}
	return suite.G2().Point().Mul(k, crs.g2xi[i]), nil
}

func PRFEval(crs *Setup, suite *pairing.SuiteBn256, k kyber.Scalar, i int) (kyber.Point, error) {
	if i < 0 || i >= crs.B {
		return nil, fmt.Errorf("evaluation index out of domain. Domain: [0, %d-1], index: %d", crs.B, i)
	}
	return suite.GT().Point().Mul(k, crs.gTzi[i]), nil
}

func PRFPEval(crs *Setup, suite *pairing.SuiteBn256, kp kyber.Point, pi, i int) (kyber.Point, error) {
	if i < 0 || i >= crs.B {
		return nil, fmt.Errorf("punctured evaluation index out of domain. Domain: [0, %d-1], index: %d", crs.B, i)
	}
	if pi < 0 || pi >= crs.B {
		return nil, fmt.Errorf("punctured index out of domain for peval. Domain: [0, %d-1], index: %d", crs.B, pi)
	}
	if pi == i {
		return nil, fmt.Errorf("punctured index cannot be the same as the evaluation index")
	}
	crselem := crs.g1zixj[mkey{
		i: i,
		j: pi,
	}]
	return suite.Pair(crselem, kp), nil
}

type CT struct {
	i     int
	gamma kyber.Point
	kp    kyber.Point
	c     EGct
	MPad  kyber.Point
	cM    []byte
	m     []byte
}

func BEnc(crs *Setup, suite *pairing.SuiteBn256, pk kyber.Point, i int, m []byte) (CT, error) {
	MPad := suite.GT().Point().Pick(suite.RandomStream())
	MPadBytes, err := MPad.MarshalBinary()
	if err != nil {
		return CT{}, err
	}
	k := PRFKeyGen(crs, suite)
	kp, err := PRFPuncture(crs, suite, k, i)
	if err != nil {
		return CT{}, err
	}
	K := suite.G2().Point().Mul(k, nil)
	egct := ElGamalEncrypt(suite.G2(), pk, K)
	pad, err := PRFEval(crs, suite, k, i)
	if err != nil {
		return CT{}, err
	}
	gamma := suite.GT().Point().Add(pad, MPad)
	seed := suite.Hash().Sum(MPadBytes)
	cM := make([]byte, len(m))
	suite.XOF(seed).XORKeyStream(cM, m)
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

func BDec(crs *Setup, suite *pairing.SuiteBn256, cts []CT, sk kyber.Scalar) (kyber.Point, error) {
	if len(cts) > crs.B {
		return nil, fmt.Errorf("too many ciphertexts for the given crs")
	}
	sum := NullEGct(suite.G2())
	for _, ct := range cts {
		sum = sum.Add(suite.G2(), ct.c)
	}
	return ElGamalDecrypt(suite.G2(), sk, sum)
}

func BDecCombine(crs *Setup, suite *pairing.SuiteBn256, cts []CT, K kyber.Point) error {
	if len(cts) > crs.B {
		return fmt.Errorf("too many ciphertexts for the given crs")
	}

	for _, ct := range cts {
		prfKi, err := PRFExpEval(crs, suite, K, ct.i)
		if err != nil {
			return err
		}
		sum := suite.GT().Point().Null()
		for j := 0; j < crs.B; j++ {
			if j == ct.i {
				continue
			}
			peval, err := PRFPEval(crs, suite, cts[j].kp, cts[j].i, ct.i)
			if err != nil {
				return err
			}
			sum = suite.GT().Point().Add(sum, peval)
		}
		MPad := suite.GT().Point().Sub(suite.GT().Point().Add(ct.gamma, sum), prfKi)
		if !MPad.Equal(ct.MPad) {
			return fmt.Errorf("decryption failed on index %d, wrong MPad", ct.i)
		}
		MPadBytes, err := MPad.MarshalBinary()
		if err != nil {
			return err
		}
		seed := suite.Hash().Sum(MPadBytes)
		m := make([]byte, len(ct.cM))
		suite.XOF(seed).XORKeyStream(m, ct.cM)
		if !bytes.Equal(m, ct.m) {
			return fmt.Errorf("decryption failed on index %d", ct.i)
		}
	}
	return nil

}

func PRFExpEval(crs *Setup, suite *pairing.SuiteBn256, K kyber.Point, i int) (kyber.Point, error) {
	if i < 0 || i >= crs.B {
		return nil, fmt.Errorf("exponential evaluation index out of domain. Domain: [0, %d-1], index: %d", crs.B, i)
	}
	return suite.Pair(crs.g1zi[i], K), nil
}

func main() {
	suite := pairing.NewSuiteBn256()
	// Create a public/private keypair
	sk := suite.G2().Scalar().Pick(suite.RandomStream()) // Alice's private key
	pk := suite.Point().Mul(sk, nil)                     // Alice's public key
	crs := PRFSetup(suite, 10)
	cts := make([]CT, 10)
	for i := 0; i < 10; i++ {
		ct, err := BEnc(crs, suite, pk, i, []byte(fmt.Sprintf("Party %d", i)))
		if err != nil {
			fmt.Println(err)
			return
		}
		cts[i] = ct
	}
	K, err := BDec(crs, suite, cts, sk)
	if err != nil {
		panic(err)
	}
	err = BDecCombine(crs, suite, cts, K)
	if err != nil {
		panic(err)
	}
	fmt.Println("Decryption succeeded")
}
