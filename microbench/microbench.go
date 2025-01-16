package main

import (
	"btd/curves"
	"fmt"
	"go.dedis.ch/kyber/v4"
	"go.dedis.ch/kyber/v4/pairing/bls12381/kilic"
	"go.dedis.ch/kyber/v4/util/random"
	"testing"
)

// Inspired from dedis/kyber/util/test/benchmark.go
type PairingBench struct {
	s             curves.Suite
	XG1, YG1      kyber.Point
	xG1           kyber.Scalar
	XG2, YG2      kyber.Point
	xG2           kyber.Scalar
	XGT, YGT, ZGT kyber.Point
	xGT           kyber.Scalar
	len           int
}

func NewPairingBench(c curves.Suite) *PairingBench {
	var pb PairingBench
	rng := random.New()
	pb.xG1 = c.G1().Scalar().Pick(rng)
	pb.xG2 = c.G2().Scalar().Pick(rng)
	pb.xGT = c.GT().Scalar().Pick(rng)
	pb.XG1 = c.G1().Point().Pick(rng)
	pb.YG1 = c.G1().Point().Pick(rng)
	pb.XG2 = c.G2().Point().Pick(rng)
	pb.YG2 = c.G2().Point().Pick(rng)
	pb.XGT = c.PickGT()
	pb.YGT = c.PickGT()
	pb.ZGT = c.PickGT()
	pb.s = c
	return &pb
}

func (pb PairingBench) PointAdd(X, Y kyber.Point, iters int) {
	for i := 1; i < iters; i++ {
		X.Add(X, Y)
	}
}

func (pb PairingBench) PointMul(x kyber.Scalar, X kyber.Point, iters int) {
	for i := 1; i < iters; i++ {
		X.Mul(x, X)
	}
}

func (pb PairingBench) Pair(X, Y kyber.Point, iters int) {

	for i := 1; i < iters; i++ {
		pb.s.Pair(X, Y)
	}
}

func main() {
	suite := curves.NewSuite(kilic.NewBLS12381Suite())
	pb := NewPairingBench(suite)
	result := make(map[string]testing.BenchmarkResult)

	A, B := pb.XG1.Clone(), pb.YG1.Clone()
	result["G1-Add"] = testing.Benchmark(func(b *testing.B) {
		pb.PointAdd(A, B, b.N)
	})
	c, D := pb.xG1.Clone(), pb.XG1.Clone()
	result["G1-Mul"] = testing.Benchmark(func(b *testing.B) {
		pb.PointMul(c, D, b.N)
	})
	E, F := pb.XG2.Clone(), pb.YG2.Clone()
	result["G2-Add"] = testing.Benchmark(func(b *testing.B) {
		pb.PointAdd(E, F, b.N)
	})
	g, H := pb.xG2.Clone(), pb.XG2.Clone()
	result["G2-Mul"] = testing.Benchmark(func(b *testing.B) {
		pb.PointMul(g, H, b.N)
	})
	I, J := pb.XGT.Clone(), pb.YGT.Clone()
	result["GT-Add"] = testing.Benchmark(func(b *testing.B) {
		pb.PointAdd(I, J, b.N)
	})
	k, L := pb.xGT.Clone(), pb.XGT.Clone()
	result["GT-Mul"] = testing.Benchmark(func(b *testing.B) {
		pb.PointMul(k, L, b.N)
	})
	M, N := pb.XG1.Clone(), pb.XG2.Clone()
	result["Pairing"] = testing.Benchmark(func(b *testing.B) {
		pb.Pair(M, N, b.N)
	})
	for k, v := range result {
		fmt.Printf("%s: %s\n", k, v)
	}
}
