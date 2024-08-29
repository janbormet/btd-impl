package main_test

import (
	"btd/be"
	"fmt"
	"go.dedis.ch/kyber/v4"
	"go.dedis.ch/kyber/v4/pairing"
	"go.dedis.ch/kyber/v4/share"
	"math"
	"sync"
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

func BenchmarkPDec8(b *testing.B) {
	testBenchmarkPDec(b, 8)
}

func BenchmarkPDec32(b *testing.B) {
	testBenchmarkPDec(b, 32)
}
func BenchmarkPDec128(b *testing.B) {
	testBenchmarkPDec(b, 128)
}

func BenchmarkPDec512(b *testing.B) {
	testBenchmarkPDec(b, 512)
}

func testBenchmarkPDec(b *testing.B, B int) {
	suite := pairing.NewSuiteBn256()
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

	b.Run(fmt.Sprintf("normal: B=%d", B), func(b *testing.B) {
		testBatchDec(b, R, B, btd, ctsR)
	})
	b.Run(fmt.Sprintf("sqrt: B=%d", B), func(b *testing.B) {
		testBatchDecSqrt(b, R, B, btd, ctsR)
	})
	b.Run(fmt.Sprintf("sqrtlog: B=%d", B), func(b *testing.B) {
		testBatchDecSqrtLog(b, R, B, btd, ctsR)
	})

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

func testBatchDecSqrt(b *testing.B, R, B int, btd *be.BTD, ctsR [][]be.CT) {
	SubCtsR := make([][][]be.CT, R)
	sqrtB := int(math.Floor(math.Sqrt(float64(B))))
	for i := 0; i < R; i++ {
		SubCtsR[i] = make([][]be.CT, sqrtB)
		for j := 0; j < sqrtB; j++ {
			start := j * sqrtB
			end := (j + 1) * sqrtB
			if j == sqrtB-1 {
				end = B
			}
			SubCtsR[i][j] = ctsR[i][start:end]
		}
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		for j := 0; j < sqrtB; j++ {
			_, err := btd.BatchDec(SubCtsR[i%R][j], 0, true)
			if err != nil {
				b.Error(err)
			}
		}
	}
}

func testBatchDecSqrtLog(b *testing.B, R, B int, btd *be.BTD, ctsR [][]be.CT) {
	SubCtsR := make([][][]be.CT, R)
	sqrtB := int(math.Floor(math.Sqrt(float64(B))))
	for i := 0; i < R; i++ {
		SubCtsR[i] = make([][]be.CT, sqrtB)
		for j := 0; j < sqrtB; j++ {
			start := j * sqrtB
			end := (j + 1) * sqrtB
			if j == sqrtB-1 {
				end = B
			}
			SubCtsR[i][j] = ctsR[i][start:end]
		}
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		for j := 0; j < sqrtB; j++ {
			_, err := btd.BatchDecOpt(SubCtsR[i%R][j], 0, true)
			if err != nil {
				b.Error(err)
			}
		}
	}
}

func BenchmarkBatchCombine8(b *testing.B) {
	testBenchmarkBatchCombine(b, 8, false)
}

func BenchmarkBatchCombine32(b *testing.B) {
	testBenchmarkBatchCombine(b, 32, false)
}

func BenchmarkBatchCombine128(b *testing.B) {
	testBenchmarkBatchCombine(b, 128, false)
}

func BenchmarkBatchCombine512Slow(b *testing.B) {
	testBenchmarkBatchCombine(b, 512, true)
}

func BenchmarkBatchCombine512Fast(b *testing.B) {
	testBenchmarkBatchCombine(b, 512, false)
}

func testBenchmarkBatchCombine(b *testing.B, B int, slow bool) {
	suite := pairing.NewSuiteBn256()
	btd := be.NewBTD(suite, B)
	n := 10
	t := 2
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
	if B < 512 || slow {
		b.Run(fmt.Sprintf("normal: B=%d", B), func(b *testing.B) {
			testCombine(b, R, B, t, btd, ctsR)
		})
	}
	if B < 512 || !slow {
		b.Run(fmt.Sprintf("sqrt: B=%d", B), func(b *testing.B) {
			testCombineSqrt(b, R, B, t, btd, ctsR)
		})
		b.Run(fmt.Sprintf("sqrtlog: B=%d", B), func(b *testing.B) {
			testCombineSqrtOpt(b, R, B, t, btd, ctsR)

		})
	}
}

func testCombine(b *testing.B, R, B, t int, btd *be.BTD, ctsR [][]be.CT) {
	pdecs := make([][]*share.PubShare, R)
	for i := 0; i < R; i++ {
		pdecs[i] = make([]*share.PubShare, t)
		for j := 0; j < t; j++ {
			pdec, err := btd.BatchDec(ctsR[i][:B], j, false)
			if err != nil {
				b.Error(err)
			}
			pdecs[i][j] = pdec
		}
	}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := btd.BatchCombine(ctsR[i%R][:B], pdecs[i%R], false)
		if err != nil {
			b.Error(err)
		}
	}
}

func testCombineSqrt(b *testing.B, R, B, t int, btd *be.BTD, ctsR [][]be.CT) {
	SubCtsR := make([][][]be.CT, R)
	sqrtB := int(math.Floor(math.Sqrt(float64(B))))
	for r := 0; r < R; r++ {
		SubCtsR[r] = make([][]be.CT, sqrtB)
		for j := 0; j < sqrtB; j++ {
			start := j * sqrtB
			end := (j + 1) * sqrtB
			if j == sqrtB-1 {
				end = B
			}
			SubCtsR[r][j] = ctsR[r][start:end]
		}
	}
	pdecs := make([][][]*share.PubShare, R)
	for r := 0; r < R; r++ {
		pdecs[r] = make([][]*share.PubShare, sqrtB)
		for j := 0; j < sqrtB; j++ {
			pdecs[r][j] = make([]*share.PubShare, t)
			for thresh := 0; thresh < t; thresh++ {
				d, err := btd.BatchDec(SubCtsR[r][j], thresh, false)
				if err != nil {
					panic(err)
				}
				pdecs[r][j][thresh] = d
			}

		}
	}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		for j := 0; j < sqrtB; j++ {
			_, err := btd.BatchCombine(SubCtsR[i%R][j], pdecs[i%R][j], false)
			if err != nil {
				panic(err)
			}
		}
	}
}

func testCombineSqrtOpt(b *testing.B, R, B, t int, btd *be.BTD, ctsR [][]be.CT) {
	SubCtsR := make([][][]be.CT, R)
	sqrtB := int(math.Floor(math.Sqrt(float64(B))))
	for r := 0; r < R; r++ {
		SubCtsR[r] = make([][]be.CT, sqrtB)
		for j := 0; j < sqrtB; j++ {
			start := j * sqrtB
			end := (j + 1) * sqrtB
			if j == sqrtB-1 {
				end = B
			}
			SubCtsR[r][j] = ctsR[r][start:end]
		}
	}
	pdecs := make([][][][]*share.PubShare, R)
	for r := 0; r < R; r++ {
		pdecs[r] = make([][][]*share.PubShare, sqrtB)
		for j := 0; j < sqrtB; j++ {
			pdecs[r][j] = make([][]*share.PubShare, t)
			for thresh := 0; thresh < t; thresh++ {
				d, err := btd.BatchDecOpt(SubCtsR[r][j], thresh, false)
				if err != nil {
					panic(err)
				}
				pdecs[r][j][thresh] = d
			}

		}
	}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		for j := 0; j < sqrtB; j++ {
			_, err := btd.BatchCombineOpt(SubCtsR[i%R][j], pdecs[i%R][j], false)
			if err != nil {
				panic(err)
			}
		}
	}
}

func testCombineSqrtOptParallel(b *testing.B, R, B, t int, btd *be.BTD, ctsR [][]be.CT) {
	SubCtsR := make([][][]be.CT, R)
	sqrtB := int(math.Floor(math.Sqrt(float64(B))))
	for r := 0; r < R; r++ {
		SubCtsR[r] = make([][]be.CT, sqrtB)
		for j := 0; j < sqrtB; j++ {
			start := j * sqrtB
			end := (j + 1) * sqrtB
			if j == sqrtB-1 {
				end = B
			}
			SubCtsR[r][j] = ctsR[r][start:end]
		}
	}
	pdecs := make([][][][]*share.PubShare, R)
	for r := 0; r < R; r++ {
		pdecs[r] = make([][][]*share.PubShare, sqrtB)
		for j := 0; j < sqrtB; j++ {
			pdecs[r][j] = make([][]*share.PubShare, t)
			for thresh := 0; thresh < t; thresh++ {
				d, err := btd.BatchDecOpt(SubCtsR[r][j], thresh, false)
				if err != nil {
					panic(err)
				}
				pdecs[r][j][thresh] = d
			}

		}
	}
	b.ResetTimer()
	wg := sync.WaitGroup{}
	for i := 0; i < b.N; i++ {
		for j := 0; j < sqrtB; j++ {
			wg.Add(1)
			go func(ctsSubBatch []be.CT, shares [][]*share.PubShare) {
				defer wg.Done()
				_, err := btd.BatchCombineOpt(ctsSubBatch, shares, false)
				if err != nil {
					panic(err)
				}
			}(SubCtsR[i%R][j], pdecs[i%R][j])
		}
	}
	wg.Wait()
	b.StopTimer()
}

func BenchmarkBatchCombinePar(b *testing.B) {
	suite := pairing.NewSuiteBn256()
	B := 512
	btd := be.NewBTD(suite, B)
	n := 10
	t := 2
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

	b.Run(fmt.Sprintf("parallel-sqrtlog: B=%d", B), func(b *testing.B) {
		testCombineSqrtOptParallel(b, R, B, t, btd, ctsR)
	})

}
