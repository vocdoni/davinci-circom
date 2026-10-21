package test

import (
	"math"
	"math/big"
	"testing"

	qt "github.com/frankban/quicktest"
)

// The cost sum is computed in the field: SumPow (lib/math.circom) raises
// each active field to cost_exponent (up to 255) by 8 square-and-multiply
// steps and adds the 16 terms, all mod p, and CheckBallotMode compares the
// residue with the budget. Whenever num_fields * maxValue^exponent >= p the
// integer cost and the field cost can differ, and a ballot whose integer
// cost is far above the budget is accepted when the residue of its cost
// lands in [minValueSum, budget].

// TestSoundnessCostSumIsFieldArithmetic shows the mechanism on the exact
// SumPow instance of the ballot circuit: 16 fields at 2^48 - 1 with exponent
// 6 give a sum above p whose output is the residue, while exponent 5 (the
// largest that cannot wrap at 48 bits) is exact.
func TestSoundnessCostSumIsFieldArithmetic(t *testing.T) {
	c := qt.New(t)
	r1csPath, symPath, wasm := compileTestCircuit(t, "soundness_sumpow")
	cs := loadR1CS(t, r1csPath)
	sym := loadSym(t, symPath)
	maxv := new(big.Int).Sub(bigPow2(48), big.NewInt(1))
	run := func(exp int64) (*big.Int, *big.Int) {
		vals := make([]string, nBallotFields)
		mask := make([]string, nBallotFields)
		integer := new(big.Int)
		for i := range vals {
			vals[i] = maxv.String()
			mask[i] = "1"
			integer.Add(integer, new(big.Int).Exp(maxv, big.NewInt(exp), nil))
		}
		w, err := calcWitness(t, wasm, map[string]any{"inputs": vals, "mask": mask, "exp": big.NewInt(exp).String()})
		c.Assert(err, qt.IsNil)
		c.Assert(witnessSatisfies(t, cs, w), qt.IsTrue)
		return getByName(t, sym, w, "main.out"), integer
	}
	out, integer := run(6)
	c.Assert(integer.Cmp(bn254r) > 0, qt.IsTrue)
	c.Assert(out.Cmp(modR(integer)), qt.Equals, 0)
	c.Assert(out.Cmp(integer), qt.Not(qt.Equals), 0)
	c.Assert(out.BitLen() < integer.BitLen(), qt.IsTrue)
	out, integer = run(5)
	c.Assert(integer.Cmp(bn254r) < 0, qt.IsTrue)
	c.Assert(out.Cmp(integer), qt.Equals, 0)

	// On the ballot circuit, the same mode refuses the all-max ballot only
	// because the residue of its cost happens to exceed the budget.
	mode := ballotMode{NumFields: 16, GroupSize: 16, CostExponent: 6, MaxValue: 1<<48 - 1, MaxValueSum: 1<<63 - 1}
	fields := make([]*big.Int, nBallotFields)
	for i := range fields {
		fields[i] = maxv
	}
	residue := new(big.Int)
	for range fields {
		residue.Add(residue, new(big.Int).Exp(maxv, big.NewInt(6), nil))
	}
	residue.Mod(residue, bn254r)
	c.Assert(residue.Cmp(bigPow2(63)) > 0, qt.IsTrue)
	_, err := calcWitness(t, build.prodWasm, newBallotCase(t, mode, fields, big.NewInt(1)).inputs())
	c.Assert(err, qt.IsNotNil)
}

// wrapExponent is the smallest exponent for which nf * max^e >= p, or 0 if
// none below 256: modes below it are exact in the field.
func wrapExponent(nf int, max *big.Int) int {
	for e := 1; e <= 255; e++ {
		v := new(big.Int).Exp(max, big.NewInt(int64(e)), nil)
		v.Mul(v, big.NewInt(int64(nf)))
		if v.Cmp(bn254r) >= 0 {
			return e
		}
	}
	return 0
}

// modeCostFits63 is the proposed process-creation restriction: with
// nf * max^e < 2^63 every intermediate of Pow stays below p, the sum is the
// integer cost, and both 63-bit comparators are exact.
func modeCostFits63(nf int, max *big.Int, e int) bool {
	v := new(big.Int).Exp(max, big.NewInt(int64(e)), nil)
	v.Mul(v, big.NewInt(int64(nf)))
	return v.Cmp(bigPow2(63)) < 0
}

// TestSoundnessCostWrapModes tabulates where the field cost can wrap and
// the k-list (Wagner) work to find in-range values whose residue lands in a
// budget window: with nf lists of e-th powers, a 2^w-wide window and a
// 254-bit modulus the target has 254 - w bits and the k-tree needs about
// nf * 2^((254 - w) / (1 + log2 nf)) time and memory, provided each list has
// that many values (max >= that size). Exponent 2 never wraps and nothing
// with e <= 5 wraps at 48 bits, so quadratic modes are safe; the wide-weight
// mode (maxValueSum 0, weight up to 2^88) with max >= 2^34 and e >= 8 is in
// reach of about 2^38 work.
func TestSoundnessCostWrapModes(t *testing.T) {
	c := qt.New(t)
	maxes := []struct {
		name string
		v    *big.Int
	}{
		{"2", big.NewInt(2)}, {"16", big.NewInt(16)}, {"2^10", bigPow2(10)}, {"2^20", bigPow2(20)},
		{"2^32", bigPow2(32)}, {"2^40", bigPow2(40)}, {"2^48-1", new(big.Int).Sub(bigPow2(48), big.NewInt(1))},
	}
	for _, m := range maxes {
		e16 := wrapExponent(16, m.v)
		e1 := wrapExponent(1, m.v)
		t.Logf("max %-7s wraps from exponent %3d (16 fields) / %3d (1 field); exact budget needs e <= %d (16 fields)", m.name, e16, e1, largestFitting(16, m.v))
	}
	c.Assert(wrapExponent(16, new(big.Int).Sub(bigPow2(48), big.NewInt(1))), qt.Equals, 6)
	c.Assert(wrapExponent(16, big.NewInt(2)), qt.Equals, 250)
	c.Assert(wrapExponent(16, big.NewInt(1)), qt.Equals, 0)
	for _, m := range maxes {
		c.Assert(wrapExponent(16, m.v) == 0 || wrapExponent(16, m.v) > 2, qt.IsTrue, qt.Commentf("quadratic wraps at max %s", m.name))
	}
	c.Assert(modeCostFits63(16, bigPow2(29), 2), qt.IsTrue)
	c.Assert(modeCostFits63(16, bigPow2(30), 2), qt.IsFalse)
	c.Assert(modeCostFits63(16, new(big.Int).Sub(bigPow2(48), big.NewInt(1)), 1), qt.IsTrue)

	for _, window := range []int{88, 63, 32, 10} {
		for _, nf := range []int{16, 8, 4, 2} {
			bits := float64(254-window) / (1 + math.Log2(float64(nf)))
			listOK := bits <= 48
			t.Logf("window 2^%-2d nf %2d: k-tree ~ 2^%.1f time and memory, lists of e-th powers large enough at 48 bits: %v", window, nf, bits+math.Log2(float64(nf)), listOK)
		}
	}
}

func largestFitting(nf int, max *big.Int) int {
	best := 0
	for e := 1; e <= 255; e++ {
		if modeCostFits63(nf, max, e) {
			best = e
		}
	}
	return best
}
