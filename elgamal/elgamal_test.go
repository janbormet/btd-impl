package elgamal_test

import (
	"btd/elgamal"
	"github.com/stretchr/testify/require"
	"go.dedis.ch/kyber/v4/pairing/bls12381/kilic"
	"go.dedis.ch/kyber/v4/share"
	"testing"
)

func TestElGamal(t *testing.T) {
	suite := kilic.NewBLS12381Suite()
	e := elgamal.NewElGamal(suite.G1(), suite.RandomStream())
	_, pk := e.KeyGen(10, 5)
	m := suite.G1().Point().Pick(suite.RandomStream())
	ct, _ := e.Enc(pk, m)
	d := make([]*share.PubShare, 5)
	for i := 0; i < 5; i++ {
		d[i] = e.PDec(ct, i)
	}
	_, err := e.Combine(ct, d)
	require.NoError(t, err)
}
