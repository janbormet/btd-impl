package main

import (
	"btd/be"
	"fmt"
	"go.dedis.ch/kyber/v4/pairing"
)

func main() {
	suite := pairing.NewSuiteBn256()
	B := 100
	btd := be.NewBTD(suite, B)
	sk, pk := btd.KeyGen()

	cts := make([]be.CT, B)
	for i := 0; i < B; i++ {
		ct, err := btd.Enc(pk, i, []byte(fmt.Sprintf("Party %d", i)))
		if err != nil {
			fmt.Println(err)
			return
		}
		cts[i] = ct
	}
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
