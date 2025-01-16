package elgamal

import (
	"crypto/cipher"
	"fmt"
	"go.dedis.ch/kyber/v4"
	"go.dedis.ch/kyber/v4/share"
)

type ElGamal struct {
	gr      kyber.Group
	rng     cipher.Stream
	PK      kyber.Point       // Public key
	Shares  []*share.PriShare // Shamir Shares
	Sharing *share.PriPoly
	n, t    int
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

func (e *ElGamal) NullEGct() CT {
	return CT{
		A: e.gr.Point().Null(),
		B: e.gr.Point().Null(),
		m: e.gr.Point().Null(),
	}
}

func (e *ElGamal) AddCT(a, b CT) CT {
	return CT{
		A: e.gr.Point().Add(a.A, b.A),
		B: e.gr.Point().Add(a.B, b.B),
		m: e.gr.Point().Add(a.m, b.m),
	}
}

func (e *ElGamal) Sum(c []CT) CT {
	sum := e.NullEGct()
	for _, ct := range c {
		sum = e.AddCT(sum, ct)
	}
	return sum
}

func (e *ElGamal) KeyGen(n, t int) ([]*share.PriShare, kyber.Point) {
	// Sample a random master secret key.
	sk := e.gr.Scalar().Pick(e.rng)
	// Generate (t,n)-Shamir sharing.
	sharing := share.NewPriPoly(e.gr, t, sk, e.rng)
	shares := sharing.Shares(n)
	// Compute master public key
	pub := sharing.Commit(nil)

	e.Shares = shares
	e.PK = pub.Commit()
	e.Sharing = sharing
	e.n, e.t = n, t
	return shares, e.PK
}

func (e *ElGamal) Enc(pk kyber.Point, m kyber.Point) (CT, kyber.Scalar) {
	u := e.gr.Scalar().Pick(e.rng) // ephemeral private key
	A := e.gr.Point().Mul(u, nil)  // ephemeral DH public key
	S := e.gr.Point().Mul(u, pk)   // ephemeral DH shared secret
	B := S.Add(S, m)               // message blinded with secret
	return CT{
		A: A,
		B: B,
		m: m,
	}, u
}

func (e *ElGamal) PDec(c CT, i int) *share.PubShare {
	// Compute (g^u)^sk_i
	return &share.PubShare{
		I: e.Shares[i].I,
		V: e.gr.Point().Mul(e.Shares[i].V, c.A),
	}
}

func (e *ElGamal) Combine(c CT, shares []*share.PubShare) (kyber.Point, error) {
	// Interpolate t shares to compute (g^u)^msk
	S, err := share.RecoverCommit(e.gr, shares, e.t, e.n)
	if err != nil {
		return nil, err
	}
	// Decrypt the message
	m := e.gr.Point().Sub(c.B, S)
	// Assertion to check if the decryption is correct
	if !c.m.Equal(m) {
		return nil, fmt.Errorf("elgamal decryption failed")
	}
	return m, nil
}

func (e *ElGamal) Dec(sk kyber.Scalar, c CT) (
	message kyber.Point, err error) {

	S := e.gr.Point().Mul(sk, c.A)
	message = e.gr.Point().Sub(c.B, S)
	if !c.m.Equal(message) {
		return nil, fmt.Errorf("elgamal decryption failed")
	}
	return message, nil
}
