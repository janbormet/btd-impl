package be

import (
	"btd/curves"
	"btd/elgamal"
	"btd/prf"
	"fmt"
	"go.dedis.ch/kyber/v4"
	"go.dedis.ch/kyber/v4/pairing"
	"go.dedis.ch/kyber/v4/share"
	"hash"
	"math"
	"strconv"
)

type Proof struct {
	Ap   kyber.Point
	Bp   kyber.Point
	yp   kyber.Point
	kHat kyber.Scalar
	uHat kyber.Scalar
}

type CT struct {
	i     int
	gamma kyber.Point
	kp    kyber.Point
	c     elgamal.CT
	pi    Proof
	m     kyber.Point
}

type BTD struct {
	suite pairing.Suite
	prf   *prf.PRF
	eg    *elgamal.ElGamal
	B     int
	H     *Hasher
	T     int
	N     int
}

func (b *BTD) VerifyCT(ct CT) bool {
	h, err := b.SHash(b.eg.PK, ct, ct.pi.Ap, ct.pi.Bp, ct.pi.yp)
	if err != nil {
		panic(err)
	}
	al := b.suite.G1().Point().Mul(ct.pi.uHat, nil)
	ar := b.suite.G1().Point().Add(ct.pi.Ap, b.suite.G1().Point().Mul(h, ct.c.A))
	if !al.Equal(ar) {
		panic("proof failed")
	}
	bl := b.suite.G1().Point().Add(b.suite.G1().Point().Mul(ct.pi.uHat, b.eg.PK), b.suite.G1().Point().Mul(ct.pi.kHat, nil))
	br := b.suite.G1().Point().Add(ct.pi.Bp, b.suite.G1().Point().Mul(h, ct.c.B))
	if !bl.Equal(br) {
		panic("proof failed")
	}
	yl := b.suite.G1().Point().Mul(ct.pi.kHat, b.prf.G1xi[ct.i])
	yr := b.suite.G1().Point().Add(ct.pi.yp, b.suite.G1().Point().Mul(h, ct.kp))
	if !yl.Equal(yr) {
		panic("proof failed")
	}
	return true
}

func NewBTD(suite curves.Suite, B int) *BTD {
	prf := prf.PRFSetup(suite, B, true)
	eg := elgamal.NewElGamal(suite.G1(), suite.RandomStream())
	return &BTD{
		suite: suite,
		prf:   prf,
		eg:    eg,
		B:     B,
		H:     &Hasher{hash: suite.Hash()},
	}
}

func (b *BTD) KeyGen(n, t int) ([]*share.PriShare, kyber.Point) {
	sk, pk := b.eg.KeyGen(n, t)
	b.T, b.N = t, n
	return sk, pk
}

func (b *BTD) Enc(pk kyber.Point, i int, m kyber.Point) (CT, error) {
	k := b.prf.KeyGen()
	kp, err := b.prf.Puncture(k, i)
	if err != nil {
		return CT{}, err
	}
	K := b.suite.G1().Point().Mul(k, nil)
	egct, u := b.eg.Enc(pk, K)
	pad, err := b.prf.Eval(k, i)
	if err != nil {
		return CT{}, err
	}
	gamma := b.suite.GT().Point().Add(pad, m)
	uN := b.suite.G1().Scalar().Pick(b.suite.RandomStream())
	kN := b.suite.G1().Scalar().Pick(b.suite.RandomStream())
	Ap := b.suite.G1().Point().Mul(uN, nil)
	Bp := b.suite.G1().Point().Add(b.suite.G1().Point().Mul(uN, b.eg.PK), b.suite.G1().Point().Mul(kN, nil))
	yp := b.suite.G1().Point().Mul(kN, b.prf.G1xi[i])
	ct := CT{
		i:     i,
		gamma: gamma,
		kp:    kp,
		c:     egct,
		m:     m,
	}
	h, err := b.SHash(pk, ct, Ap, Bp, yp)
	if err != nil {
		return CT{}, err
	}
	uHat := b.suite.G1().Scalar().Add(uN, b.suite.G1().Scalar().Mul(u, h))
	kHat := b.suite.G1().Scalar().Add(kN, b.suite.G1().Scalar().Mul(k, h))
	ct.pi = Proof{
		Ap:   Ap,
		Bp:   Bp,
		yp:   yp,
		kHat: kHat,
		uHat: uHat,
	}
	return ct, nil
}

func (b *BTD) BatchDec(cts []CT, i int, verify bool) (*share.PubShare, error) {
	if len(cts) > b.B {
		return nil, fmt.Errorf("too many ciphertexts for the given crs")
	}
	C, err := b.SumEGCt(cts, verify)
	if err != nil {
		return nil, err
	}
	return b.eg.PDec(C, i), nil
}

func (b *BTD) BatchCombine(cts []CT, d []*share.PubShare, verify bool) (int, error) {
	count := 0
	ActualB := len(cts)
	if ActualB > b.B {
		return count, fmt.Errorf("too many ciphertexts for the given crs")
	}
	C, err := b.SumEGCt(cts, verify)
	if err != nil {
		return count, err
	}
	K, err := b.eg.Combine(C, d)
	if err != nil {
		return count, err
	}
	for _, ct := range cts {
		count++
		prfKi, err := b.prf.ExpEval(K, ct.i)
		if err != nil {
			return count, err
		}
		sum := b.suite.GT().Point().Null()
		for j := 0; j < ActualB; j++ {
			ji := cts[j].i
			if ji == ct.i {
				continue
			}
			count++
			peval, err := b.prf.PEval(cts[j].kp, ji, ct.i)
			if err != nil {
				str := fmt.Sprintf("PEval on puncutured index %d on index %d failed: ", cts[j].i, ct.i)
				for _, c := range cts {
					str += fmt.Sprintf("%d ", c.i)
				}
				panic(str)
				return count, err
			}
			sum = b.suite.GT().Point().Add(sum, peval)
		}
		m := b.suite.GT().Point().Sub(b.suite.GT().Point().Add(ct.gamma, sum), prfKi)
		if !m.Equal(ct.m) {
			return count, fmt.Errorf("decryption failed on index %d", ct.i)
		}
	}
	return count, nil
}

func (b *BTD) BatchDecOpt(cts []CT, i int, verify bool) ([]*share.PubShare, error) {
	L := len(cts)
	if L > b.B {
		return nil, fmt.Errorf("too many ciphertexts for the given crs")
	}
	if verify {
		for _, ct := range cts {
			if !b.VerifyCT(ct) {
				return nil, fmt.Errorf("proof failed for index %d", ct.i)
			}
		}
	}
	lgL := int(math.Ceil(math.Log2(float64(L))))
	Ks := make([]*share.PubShare, lgL)
	var err error
	for l := 0; l < lgL; l++ {
		x := math.Pow(2, float64(l))
		start := int(math.Floor(float64(L) * (x - 1.0) / x))
		Ks[l], err = b.BatchDec(cts[start:], i, false)
		if err != nil {
			return nil, err
		}
	}
	return Ks, nil
}

func (b *BTD) BatchCombineOptOld(cts []CT, ShareKs [][]*share.PubShare, verify bool) (int, error) {
	count := 0
	L := len(cts)
	if L > b.B {
		return count, fmt.Errorf("too many ciphertexts for the given crs")
	}
	lgL := int(math.Ceil(math.Log2(float64(L))))
	Ks := make([]kyber.Point, lgL)
	for l := 0; l < lgL; l++ {
		x := math.Pow(2, float64(l))
		start := int(math.Floor(float64(L) * (x - 1.0) / x))
		shares := make([]*share.PubShare, len(ShareKs))
		for j, s := range ShareKs {
			shares[j] = s[l]
		}
		C, err := b.SumEGCt(cts[start:], verify)
		if err != nil {
			return count, err
		}
		Ks[l], err = b.eg.Combine(C, shares)
		if err != nil {
			return count, err
		}
	}
	KsIdx := 1
	for idx, ct := range cts {
		count++
		prfKi, err := b.prf.ExpEval(Ks[0], ct.i)
		if err != nil {
			return count, err
		}
		sum := b.suite.GT().Point().Null()
		x := math.Pow(2, float64(KsIdx))
		nextStart := int(math.Floor(float64(L) * (x - 1.0) / x))
		if idx >= nextStart {
			KsIdx++
		}
		if idx > 0 {
			for j := 0; j < idx; j++ {
				count++
				peval, err := b.prf.PEval(cts[j].kp, cts[j].i, ct.i)
				if err != nil {
					return count, err
				}
				sum = b.suite.GT().Point().Add(sum, peval)
			}
		}
		for j := idx + 1; j < L; j++ {
			var eval kyber.Point
			if KsIdx < len(Ks) && j == nextStart {
				count++
				eval, err = b.prf.ExpEval(Ks[KsIdx], ct.i)
				if err != nil {
					return count, err
				}
				sum = b.suite.GT().Point().Add(sum, eval)
				break
			}
			count++
			eval, err = b.prf.PEval(cts[j].kp, cts[j].i, ct.i)
			if err != nil {
				return count, err
			}
			sum = b.suite.GT().Point().Add(sum, eval)

		}
		m := b.suite.GT().Point().Sub(b.suite.GT().Point().Add(ct.gamma, sum), prfKi)
		if !m.Equal(ct.m) {
			return count, fmt.Errorf("decryption failed on index %d", ct.i)
		}
	}
	return count, nil
}

func (b *BTD) BatchCombineOpt(cts []CT, ShareKs [][]*share.PubShare, verify bool) (int, error) {
	count := 0
	L := len(cts)
	if L > b.B {
		return count, fmt.Errorf("too many ciphertexts for the given crs")
	}
	lgL := int(math.Ceil(math.Log2(float64(L))))
	Ks := make([]kyber.Point, lgL)
	for l := 0; l < lgL; l++ {
		x := math.Pow(2, float64(l))
		start := int(math.Floor(float64(L) * (x - 1.0) / x))
		shares := make([]*share.PubShare, len(ShareKs))
		for j, s := range ShareKs {
			shares[j] = s[l]
		}
		C, err := b.SumEGCt(cts[start:], verify)
		if err != nil {
			return count, err
		}
		Ks[l], err = b.eg.Combine(C, shares)
		if err != nil {
			return count, err
		}
	}
	KsIdx := 1
	oldStart := 0
	for idx, ct := range cts {
		count++
		sum := b.suite.GT().Point().Null()
		x := math.Pow(2, float64(KsIdx))
		nextStart := int(math.Floor(float64(L) * (x - 1.0) / x))

		if idx >= nextStart && KsIdx+1 < len(Ks) {
			KsIdx++
			oldStart = nextStart
			nextX := math.Pow(2, float64(KsIdx))
			nextNextStart := int(math.Floor(float64(L) * (nextX - 1.0) / nextX))
			nextStart = nextNextStart
		}
		prfKi, err := b.prf.ExpEval(Ks[KsIdx-1], ct.i)
		if err != nil {
			return count, err
		}
		if idx > oldStart {
			for j := oldStart; j < idx; j++ {
				count++
				peval, err := b.prf.PEval(cts[j].kp, cts[j].i, ct.i)
				if err != nil {
					return count, err
				}
				sum = b.suite.GT().Point().Add(sum, peval)
			}
		}
		for j := idx + 1; j < L; j++ {
			var eval kyber.Point

			if KsIdx < len(Ks) && j == nextStart {
				count++
				eval, err = b.prf.ExpEval(Ks[KsIdx], ct.i)
				if err != nil {
					return count, err
				}
				sum = b.suite.GT().Point().Add(sum, eval)
				break
			}
			count++
			eval, err = b.prf.PEval(cts[j].kp, cts[j].i, ct.i)
			if err != nil {
				return count, err
			}
			sum = b.suite.GT().Point().Add(sum, eval)

		}
		m := b.suite.GT().Point().Sub(b.suite.GT().Point().Add(ct.gamma, sum), prfKi)
		if !m.Equal(ct.m) {
			return count, fmt.Errorf("decryption failed on index %d", ct.i)
		}
	}
	return count, nil
}

func (b *BTD) BatchCombineOptNotWorking(cts []CT, SharesK []*share.PubShare, SharesKUpper [][]*share.PubShare, SharesKLower [][]*share.PubShare, verify bool) (int, error) {
	count := 0
	L := len(cts)
	if L > b.B {
		return count, fmt.Errorf("too many ciphertexts for the given crs")
	}
	lgL := int(math.Ceil(math.Log2(float64(L))))
	C, err := b.SumEGCt(cts, verify)
	if err != nil {
		return count, err
	}
	K, err := b.eg.Combine(C, SharesK)
	if err != nil {
		return count, err
	}
	KUpper := make([]kyber.Point, lgL-1)
	KLower := make([]kyber.Point, lgL-1)
	for l := 1; l < lgL; l++ {
		x := math.Pow(2, float64(l))
		start := int(math.Floor(float64(L) * (x - 1.0) / x))
		sharesUpper := make([]*share.PubShare, len(SharesKUpper))
		sharesLower := make([]*share.PubShare, len(SharesKLower))
		for j, s := range SharesKUpper {
			sharesUpper[j] = s[l-1]
		}
		for j, s := range SharesKLower {
			sharesLower[j] = s[l-1]
		}
		CUpper, err := b.SumEGCt(cts[start:], verify)
		if err != nil {
			return count, err
		}
		CLower, err := b.SumEGCt(cts[:start], verify)
		if err != nil {
			return count, err
		}
		KUpper[l-1], err = b.eg.Combine(CUpper, sharesUpper)
		if err != nil {
			return count, err
		}
		KLower[l-1], err = b.eg.Combine(CLower, sharesLower)
	}
	UpperIdx := 0
	LowerIdx := -1
	oldStart := 0
	oldNextStart := 0
	for idx, ct := range cts {
		count++
		prfKi, err := b.prf.ExpEval(K, ct.i)
		if err != nil {
			return count, err
		}
		sum := b.suite.GT().Point().Null()
		x := math.Pow(2, float64(UpperIdx+1))
		nextStart := int(math.Floor(float64(L) * (x - 1.0) / x))
		if idx >= nextStart {
			UpperIdx++
			LowerIdx++
			oldStart = oldNextStart
		}
		oldNextStart = nextStart
		if idx > 0 {
			for j := idx - 1; j >= 0; j-- {
				if LowerIdx >= 0 && LowerIdx < len(KLower) && j == oldStart {
					count++
					eval, err := b.prf.ExpEval(KLower[LowerIdx], ct.i)
					if err != nil {
						return count, err
					}
					sum = b.suite.GT().Point().Add(sum, eval)
					break
				}
				count++
				peval, err := b.prf.PEval(cts[j].kp, cts[j].i, ct.i)
				if err != nil {
					return count, err
				}
				sum = b.suite.GT().Point().Add(sum, peval)
			}
		}
		for j := idx + 1; j < L; j++ {
			var eval kyber.Point
			if UpperIdx < len(KUpper) && j == nextStart {
				count++
				eval, err = b.prf.ExpEval(KUpper[UpperIdx], ct.i)
				if err != nil {
					return count, err
				}
				sum = b.suite.GT().Point().Add(sum, eval)
				break
			}
			count++
			eval, err = b.prf.PEval(cts[j].kp, cts[j].i, ct.i)
			if err != nil {
				return count, err
			}
			sum = b.suite.GT().Point().Add(sum, eval)

		}
		m := b.suite.GT().Point().Sub(b.suite.GT().Point().Add(ct.gamma, sum), prfKi)
		if !m.Equal(ct.m) {
			return count, fmt.Errorf("decryption failed on index %d", ct.i)
		}
	}
	return count, nil
}

func (b *BTD) SumEGCt(cts []CT, verify bool) (elgamal.CT, error) {
	sum := b.eg.NullEGct()
	for _, ct := range cts {
		if verify {
			if !b.VerifyCT(ct) {
				return sum, fmt.Errorf("proof failed for index %d", ct.i)
			}
		}
		sum = b.eg.AddCT(sum, ct.c)
	}
	return sum, nil
}

type Hasher struct {
	hash hash.Hash
}

func (h *Hasher) Hash(a []byte) []byte {
	h.hash.Reset()
	h.hash.Write(a)
	return h.hash.Sum(nil)
}

func (h *Hasher) Size() int {
	return h.hash.Size()
}

func (b *BTD) SHash(pk kyber.Point, c CT, Ap, Bp, yp kyber.Point) (kyber.Scalar, error) {
	h := b.suite.Hash()
	h.Reset()
	if _, err := h.Write([]byte("pp")); err != nil { // Replace with actual setup
		return nil, err

	}
	if _, err := pk.MarshalTo(h); err != nil {
		return nil, err
	}
	if _, err := Ap.MarshalTo(h); err != nil {
		return nil, err
	}
	if _, err := Bp.MarshalTo(h); err != nil {
		return nil, err
	}
	if _, err := yp.MarshalTo(h); err != nil {
		return nil, err
	}
	if _, err := h.Write([]byte(strconv.Itoa(c.i))); err != nil {
		return nil, err
	}
	if _, err := c.gamma.MarshalTo(h); err != nil {
		return nil, err
	}
	if _, err := c.kp.MarshalTo(h); err != nil {
		return nil, err
	}
	if _, err := c.c.A.MarshalTo(h); err != nil {
		return nil, err
	}
	if _, err := c.c.B.MarshalTo(h); err != nil {
		return nil, err
	}
	return b.suite.G1().Scalar().SetBytes(h.Sum(nil)), nil
}
