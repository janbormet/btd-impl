package main

import (
	"btd/be"
	"fmt"
	"go.dedis.ch/kyber/v4"
	"go.dedis.ch/kyber/v4/pairing/bls12381/circl"
	"go.dedis.ch/kyber/v4/pairing/bn254"
	"go.dedis.ch/kyber/v4/share"
	"math"
	"time"
)

func main() {
	suite := bn254.NewSuiteBn254()
	N := 1000
	g1 := make([]kyber.Point, N)
	g2 := make([]kyber.Point, N)
	gt := make([]kyber.Point, N)
	for i := 0; i < N; i++ {
		g1[i] = suite.G1().Point().Pick(suite.RandomStream())
		g2[i] = suite.G2().Point().Pick(suite.RandomStream())
	}
	fmt.Println("Start")
	start := time.Now()
	for j := 0; j < N; j++ {
		gt[j] = suite.Pair(g1[j], g2[j])
	}
	elapsed := time.Since(start)
	fmt.Printf("BN: Elapsed time for %d pairings: %s\n", N, elapsed)
}

func main2() {
	suite := circl.NewSuiteBLS12381()
	N := 1000
	g1 := make([]kyber.Point, N)
	g2 := make([]kyber.Point, N)
	gt := make([]kyber.Point, N)
	for i := 0; i < N; i++ {
		g1[i] = suite.G1().Point().Pick(suite.RandomStream())
		g2[i] = suite.G2().Point().Pick(suite.RandomStream())
	}
	fmt.Println("Start")
	start := time.Now()
	for j := 0; j < N; j++ {
		gt[j] = suite.Pair(g1[j], g2[j])
	}
	elapsed := time.Since(start)
	fmt.Printf("BLS: Elapsed time for %d pairings: %s\n", N, elapsed)
}

func mainActual() {
	suite := bn254.NewSuiteBn254()
	B := 8
	n := 10
	t := 5
	btd := be.NewBTD(suite, B)
	_, pk := btd.KeyGen(n, t)
	fmt.Println("Setup succeeded")
	m := suite.GT().Point().Pick(suite.RandomStream())
	cts := make([]be.CT, B)
	for i := 0; i < B; i++ {
		ct, err := btd.Enc(pk, i, m)
		if err != nil {
			fmt.Println(err)
			return
		}
		cts[i] = ct
	}
	fmt.Println("Encryption succeeded")
	testOptSqrt(btd, cts)
}

func testNaive(btd *be.BTD, cts []be.CT) {
	d := make([]*share.PubShare, btd.T)
	var err error
	for i := 0; i < btd.T; i++ {
		d[i], err = btd.BatchDec(cts, i, true)
		if err != nil {
			panic(err)
		}
	}
	count, err := btd.BatchCombine(cts, d, false)
	if err != nil {
		panic(err)
	}
	fmt.Println("Decryption succeeded")
	fmt.Println("Pairings for Dec:", count)
}

func testOpt(btd *be.BTD, cts []be.CT) {
	ds := make([][]*share.PubShare, btd.T)
	var err error
	for i := 0; i < btd.T; i++ {
		ds[i], err = btd.BatchDecOpt(cts, i, true)
		if err != nil {
			panic(err)
		}
	}
	count, err := btd.BatchCombineOpt(cts, ds, false)
	if err != nil {
		panic(err)
	}
	fmt.Println("Optimized Decryption succeeded")
	fmt.Println("Pairings for optimized Dec:", count)
}

func testOptSqrt(btd *be.BTD, cts []be.CT) {
	sqrtB := int(math.Floor(math.Sqrt(float64(btd.B))))
	count := 0
	for i := 0; i < sqrtB; i++ {
		start := i * sqrtB
		end := (i + 1) * sqrtB
		if i == sqrtB-1 {
			end = btd.B
		}
		ds := make([][]*share.PubShare, btd.T)
		var err error
		for j := 0; j < btd.T; j++ {
			ds[j], err = btd.BatchDecOpt(cts[start:end], j, true)
			if err != nil {
				panic(err)
			}
		}
		x, err := btd.BatchCombineOpt(cts[start:end], ds, false)
		if err != nil {
			panic(err)
		}
		count += x
	}
	fmt.Println("Optimized Decryption with sqrt(B)*log(sqrt(B)) communication succeeded")
	fmt.Println("Pairings for optimized Dec:", count)
}
