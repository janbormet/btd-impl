package main

import (
	"btd/be"
	"fmt"
	"go.dedis.ch/kyber/v4"
	"go.dedis.ch/kyber/v4/pairing"
	"go.dedis.ch/kyber/v4/share"
	"math"
	"time"
)

func main2() {
	suite := pairing.NewSuiteBn256()
	g := make([]kyber.Point, 100000)
	for i := 0; i < 100000; i++ {
		g[i] = suite.G2().Point().Pick(suite.RandomStream())
	}
	sum := suite.G2().Point().Null()
	fmt.Println("Start")
	start := time.Now()
	for j := 0; j < 100; j++ {
		for i := 0; i < 100000; i++ {
			sum = sum.Add(sum, g[i])
		}
	}
	elapsed := time.Since(start)
	fmt.Println("Elapsed time for 100000 additions:", elapsed)
}

func main() {
	suite := pairing.NewSuiteBn256()
	B := 16
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
	count, err := btd.BatchCombine(cts, d)
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
	count, err := btd.BatchCombineOpt(cts, ds)
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
		x, err := btd.BatchCombineOpt(cts[start:end], ds)
		if err != nil {
			panic(err)
		}
		count += x
	}
	fmt.Println("Optimized Decryption with sqrt(B)*log(sqrt(B)) communication succeeded")
	fmt.Println("Pairings for optimized Dec:", count)
}
