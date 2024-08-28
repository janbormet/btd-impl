package main

import (
	"btd/be"
	"fmt"
	"go.dedis.ch/kyber/v4"
	"go.dedis.ch/kyber/v4/pairing"
	"math"
	"time"
)

func main() {
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

func main2() {
	suite := pairing.NewSuiteBn256()
	B := 500
	btd := be.NewBTD(suite, B)
	sk, pk := btd.KeyGen()
	fmt.Println("Setup succeeded")
	cts := make([]be.CT, B)
	for i := 0; i < B; i++ {
		ct, err := btd.Enc(pk, i, []byte(fmt.Sprintf("Party %d", i)))
		if err != nil {
			fmt.Println(err)
			return
		}
		cts[i] = ct
	}
	fmt.Println("Encryption succeeded")
	testOptSqrt(btd, sk, cts)
}

func testNaive(btd *be.BTD, sk kyber.Scalar, cts []be.CT) {
	K, err := btd.BatchDec(cts, sk)
	if err != nil {
		panic(err)
	}
	count, err := btd.BatchCombine(cts, K)
	if err != nil {
		panic(err)
	}
	fmt.Println("Decryption succeeded")
	fmt.Println("Pairings for Dec:", count)
}

func testOpt(btd *be.BTD, sk kyber.Scalar, cts []be.CT) {
	Ks, err := btd.BatchDecOpt(cts, sk)
	if err != nil {
		panic(err)
	}
	count, err := btd.BatchCombineOpt(cts, Ks)
	if err != nil {
		panic(err)
	}
	fmt.Println("Optimized Decryption succeeded")
	fmt.Println("Pairings for optimized Dec:", count)
}

func testOptSqrt(btd *be.BTD, sk kyber.Scalar, cts []be.CT) {
	sqrtB := int(math.Floor(math.Sqrt(float64(btd.B))))
	count := 0
	for i := 0; i < sqrtB; i++ {
		start := i * sqrtB
		end := (i + 1) * sqrtB
		if i == sqrtB-1 {
			end = btd.B
		}
		sqrtKs, err := btd.BatchDecOpt(cts[start:end], sk)
		if err != nil {
			panic(err)
		}
		x, err := btd.BatchCombineOpt(cts[start:end], sqrtKs)
		count += x
	}
	fmt.Println("Optimized Decryption with sqrt(B)*log(sqrt(B)) communication succeeded")
	fmt.Println("Pairings for optimized Dec:", count)
}
