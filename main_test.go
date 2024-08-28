package main_test

import (
	"btd/be"
	"fmt"
	"go.dedis.ch/kyber/v4"
	"go.dedis.ch/kyber/v4/pairing"
	"testing"
)

func BenchmarkEnc(b *testing.B) {
	suite := pairing.NewSuiteBn256()
	B := 16
	btd := be.NewBTD(suite, B)
	R := 100
	Ms := make([]kyber.Point, R)
	for i := 0; i < R; i++ {
		Ms[i] = suite.GT().Point().Pick(suite.RandomStream())
	}
	n := 10
	t := 5
	_, pk := btd.KeyGen(n, t)
	b.StartTimer()
	for i := 0; i < b.N; i++ {
		_, err := btd.Enc(pk, 0, Ms[i%R])
		if err != nil {
			b.Error(err)
		}
	}
	b.StopTimer()
}

func BenchmarkPDec(b *testing.B) { // NEED TO FIX b.N !
	suite := pairing.NewSuiteBn256()
	B := 512
	btd := be.NewBTD(suite, B)
	n := 10
	t := 5
	R := 50
	Ms := make([]kyber.Point, R)
	for i := 0; i < R; i++ {
		Ms[i] = suite.GT().Point().Pick(suite.RandomStream())

	}
	_, pk := btd.KeyGen(n, t)
	ctsR := make([][]be.CT, R)
	for j := 0; j < R; j++ {
		cts := make([]be.CT, B)
		for i := 0; i < B; i++ {
			ct, err := btd.Enc(pk, i, Ms[j])
			if err != nil {
				b.Error(err)
			}
			cts[i] = ct
		}
		ctsR[j] = cts
	}
	Bs := []int{8, 32, 128, 512}
	for _, tB := range Bs {
		b.Run(fmt.Sprintf("B = %d", tB), func(b *testing.B) {
			testBatchDec(b, R, tB, btd, ctsR)
		})

	}
}

func testBatchDec(b *testing.B, R, B int, btd *be.BTD, ctsR [][]be.CT) {
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := btd.BatchDec(ctsR[i%R][:B], 0, true)
		if err != nil {
			b.Error(err)
		}
	}
}
