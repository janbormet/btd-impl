package elgamal

import (
	"crypto/cipher"
	"fmt"
	"go.dedis.ch/kyber/v4"
)

type ElGamal struct {
	gr  kyber.Group
	rng cipher.Stream
}

func NewElGamal(gr kyber.Group, rng cipher.Stream) *ElGamal {
	return &ElGamal{
		gr:  gr,
		rng: rng,
	}
}

type CT struct {
	A kyber.Point
	B kyber.Point
	m kyber.Point
}

func (e ElGamal) NullEGct() CT {
	return CT{
		A: e.gr.Point().Null(),
		B: e.gr.Point().Null(),
		m: e.gr.Point().Null(),
	}
}

func (e ElGamal) AddCT(a, b CT) CT {
	return CT{
		A: e.gr.Point().Add(a.A, b.A),
		B: e.gr.Point().Add(a.B, b.B),
		m: e.gr.Point().Add(a.m, b.m),
	}
}

func (e ElGamal) KeyGen() (kyber.Scalar, kyber.Point) {
	sk := e.gr.Scalar().Pick(e.rng)
	pk := e.gr.Point().Mul(sk, nil)
	return sk, pk
}

func (e ElGamal) Enc(pk kyber.Point, m kyber.Point) CT {
	k := e.gr.Scalar().Pick(e.rng) // ephemeral private key
	A := e.gr.Point().Mul(k, nil)  // ephemeral DH public key
	S := e.gr.Point().Mul(k, pk)   // ephemeral DH shared secret
	B := S.Add(S, m)               // message blinded with secret
	return CT{
		A: A,
		B: B,
		m: m,
	}
}

func (e ElGamal) Dec(sk kyber.Scalar, c CT) (
	message kyber.Point, err error) {

	S := e.gr.Point().Mul(sk, c.A)
	message = e.gr.Point().Sub(c.B, S)
	if !c.m.Equal(message) {
		return nil, fmt.Errorf("elgamal decryption failed")
	}
	return message, nil
}
