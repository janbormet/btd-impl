package main

import (
	"btd/be"
	"fmt"
	"go.dedis.ch/kyber/v4"
	"go.dedis.ch/kyber/v4/pairing"
	"math"
	"math/rand"
	"sync"
	"time"
)

func main() {
	sqrtB := 2
	d := 1
	B := sqrtB * sqrtB
	P := 8
	N := P * 1_000_000
	domain := B * B
	set := make([]int, B)
	for i := 0; i < B; i++ {
		set[i] = i
	}
	combs := combinations(set, sqrtB)
	fmt.Println(combs)
	fmt.Println("--------")
	allCombs := combinationsSB(combs, sqrtB)
	fmt.Println(allCombs)

	succ, fail := parallelSimulations(domain, sqrtB, d, N, P, allCombs)
	fmt.Println("Simulation for B=", B, "sqrt(B)=", sqrtB, "domain:", domain, "d:", d, "Simulations:", N)
	fmt.Println("Successes:", succ)
	fmt.Println("Failures:", fail)
	fmt.Println("Success rate:", float64(succ)/float64(N))
}

func parallelSimulations(domain, sqrtB, d, N, P int, allCombs [][]SubBatch) (int, int) {
	seed := time.Now().UnixNano()
	var wg sync.WaitGroup
	succCh := make(chan int, P) // Channel to collect success counts
	failCh := make(chan int, P) // Channel to collect failure counts

	// Calculate the number of simulations each goroutine will handle
	simsPerRoutine := N / P

	// Start P goroutines
	for i := 0; i < P; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			localSucc := 0
			localFail := 0
			localRNG := rand.New(rand.NewSource(seed + int64(i)))
			for j := 0; j < simsPerRoutine; j++ {
				if doSimulation(domain, sqrtB, d, allCombs, localRNG) {
					localSucc++
				} else {
					localFail++
				}
			}

			// Send results to channels
			succCh <- localSucc
			failCh <- localFail
		}()
	}

	// Wait for all goroutines to finish
	go func() {
		wg.Wait()
		close(succCh)
		close(failCh)
	}()

	// Aggregate results from channels
	totalSucc := 0
	totalFail := 0
	for succ := range succCh {
		totalSucc += succ
	}
	for fail := range failCh {
		totalFail += fail
	}

	return totalSucc, totalFail
}

func doSimulation(domain, sqrtB, d int, allCombs [][]SubBatch, rng *rand.Rand) bool {
	samples := sim(domain, sqrtB, d, rng)
outer:
	for _, sol := range allCombs {
		for _, sb := range sol {
			if !sb.matchPossible(samples) {
				continue outer
			}
		}
		//fmt.Println("Solution found for matching:")
		//fmt.Println(sol)
		//fmt.Println("with sampling")
		//fmt.Println(samples)
		return true
	}
	// fmt.Println("No solution found")
	return false
}

type SubBatch struct {
	parties []int
}

// Helper function for DFS
func dfs(u int, match []int, visited []bool, graph [][]bool) bool {
	for v := 0; v < len(graph[0]); v++ {
		if graph[u][v] && !visited[v] {
			visited[v] = true
			if match[v] == -1 || dfs(match[v], match, visited, graph) {
				match[v] = u
				return true
			}
		}
	}
	return false
}

// Function to check if each party can be assigned a unique sample
func (sb SubBatch) matchPossible(allSamples [][]int) bool {
	pSamples := make([][]int, len(sb.parties))
	for i, p := range sb.parties {
		pSamples[i] = allSamples[p]
	}
	L := len(pSamples)
	if L == 0 {
		return true
	}

	// Collect unique samples
	sampleSet := make(map[int]bool)
	for _, choices := range pSamples {
		for _, sample := range choices {
			sampleSet[sample] = true
		}
	}

	// Convert sampleSet to slice
	samples := make([]int, 0, len(sampleSet))
	for s := range sampleSet {
		samples = append(samples, s)
	}

	// Create bipartite graph
	graph := make([][]bool, L)
	for i := range graph {
		graph[i] = make([]bool, len(samples))
	}

	sampleIndex := make(map[int]int)
	for i, s := range samples {
		sampleIndex[s] = i
	}

	// Build the graph
	for i, choices := range pSamples {
		for _, choice := range choices {
			if idx, exists := sampleIndex[choice]; exists {
				graph[i][idx] = true
			}
		}
	}

	// Bipartite matching
	match := make([]int, len(samples))
	for i := range match {
		match[i] = -1
	}

	result := 0
	for u := 0; u < L; u++ {
		visited := make([]bool, len(samples))
		if dfs(u, match, visited, graph) {
			result++
		}
	}

	return result == L
}

func (sb SubBatch) String() string {
	return fmt.Sprintf("%v", sb.parties)
}

func (sb SubBatch) contains(i int) bool {
	for _, p := range sb.parties {
		if p == i {
			return true
		}
	}
	return false
}

func (sb SubBatch) overlaps(other SubBatch) bool {
	for _, p := range sb.parties {
		if other.contains(p) {
			return true
		}
	}
	return false
}
func (sb SubBatch) append(other SubBatch) SubBatch {
	r := make([]int, len(sb.parties)+len(other.parties))
	copy(r[:len(sb.parties)], sb.parties)
	copy(r[len(sb.parties):], other.parties)
	return SubBatch{parties: r}
}

func sim(domain, sqrtB, d int, rng *rand.Rand) [][]int {
	B := sqrtB * sqrtB
	samples := make([][]int, B)
	for i := 0; i < B; i++ {
		samples[i] = make([]int, d)
		for j := 0; j < d; j++ {
			samples[i][j] = rng.Intn(domain)
		}
	}
	return samples
}

// Helper function to generate combinations
func combinations(set []int, combSize int) []SubBatch {
	var result []SubBatch
	comb := make([]int, combSize)

	var backtrack func(start, depth int)
	backtrack = func(start, depth int) {
		if depth == combSize {
			// Make a copy of the current combination and append it to result
			combination := make([]int, combSize)
			copy(combination, comb)
			result = append(result, SubBatch{parties: combination})
			return
		}
		for i := start; i < len(set); i++ {
			comb[depth] = set[i]
			backtrack(i+1, depth+1)
		}
	}

	backtrack(0, 0)
	return result
}

// Helper function to generate combinations
func combinationsSB(set []SubBatch, combSize int) [][]SubBatch {
	var result [][]SubBatch
	comb := make([]SubBatch, combSize)

	var backtrack func(chosen SubBatch, start, depth int)
	backtrack = func(chosen SubBatch, start, depth int) {
		if depth == combSize {
			// Make a copy of the current combination and append it to result
			combination := make([]SubBatch, combSize)
			copy(combination, comb)
			result = append(result, combination)
			return
		}
		for i := start; i < len(set); i++ {
			if chosen.overlaps(set[i]) {
				continue
			}
			comb[depth] = set[i]
			backtrack(chosen.append(set[i]), i+1, depth+1)
		}
	}

	backtrack(SubBatch{make([]int, 0)}, 0, 0)
	return result
}

func runTest() {
	suite := pairing.NewSuiteBn256()
	B := 100
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
