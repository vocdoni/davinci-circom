package test

import (
	"fmt"
	"math/big"
	"testing"

	qt "github.com/frankban/quicktest"
)

// The weight-budget mode (maxValueSum = 0) compares the cost sum with the
// voter weight through LessEqThan(ValueSumCmpBits()) = LessEqThan(89)
// (ballot_protocol.circom), which decomposes `cost + 2^89 - weight - 1` into
// 90 bits and reads bit 89. That is exact while both sides are below 2^89;
// census weights are below 2^88 (CIRCUIT.md: bits 0..87 of the leaf, CSP
// weights < 2^88) and the registry keeps every mode's integer cost below
// 2^63, so every honest ballot has a witness.
//
// For a weight W the upper-bound constraints accept a cost C exactly when
// C + 2^89 - W - 1 lies in [0, 2^89), that is W + 1 - 2^89 <= C <= W; the
// lower bound, LessEqThan(89)(minValueSum, C), needs
// minValueSum + 2^89 - C - 1 in [0, 2^89), that is C <= minValueSum + 2^89 - 1.
// Costs outside either window have no satisfying witness at all: the 90-bit
// decomposition cannot represent a field element in [2^90, p).

// valueSumCmpBits is ValueSumCmpBits() in ballot_protocol.circom.
const valueSumCmpBits = 89

// budgetAccepts is what the two comparators enforce, derived above.
func budgetAccepts(cost, weight *big.Int) bool {
	return comparatorWindow(cost, weight) && comparatorWindow(big.NewInt(0), cost)
}

// comparatorWindow is LessEqThan(89)(a, b): a + 2^89 - b - 1 decomposes into
// 90 bits with bit 89 clear.
func comparatorWindow(a, b *big.Int) bool {
	in := new(big.Int).Add(a, bigPow2(valueSumCmpBits))
	in.Sub(in, b)
	in.Sub(in, big.NewInt(1))
	in.Mod(in, bn254r)
	return in.Cmp(bigPow2(valueSumCmpBits)) < 0
}

func budgetVectors() (weights, costs []*big.Int) {
	weights = []*big.Int{
		new(big.Int).Sub(bigPow2(63), big.NewInt(1)),
		bigPow2(63),
		new(big.Int).Add(bigPow2(63), big.NewInt(5)),
		bigPow2(64),
		new(big.Int).Sub(bigPow2(88), big.NewInt(1)),
	}
	costs = ints(0, 1, 5, 6)
	return
}

// budgetCase is a one-field ballot whose field value is the cost (exponent 1,
// min sums 0, maxValueSum 0 so the weight is the budget).
func budgetCase(t *testing.T, cost, weight *big.Int) *ballotCase {
	t.Helper()
	return newBallotCase(t, simpleMode(1, 1<<48-1, 0, 1), []*big.Int{cost}, weight)
}

// TestSoundnessBudgetWeightAbove63BitsRefusesHonestBallots: a voter whose
// weight is at or above 2^63 (about 9.2 tokens of an ERC-20 census in wei)
// casts every ballot whose cost is at most the weight, up to weights of
// 2^88 - 1. With 63-bit comparators weight 2^63 refused cost 0 and weight
// 2^64 refused every cost.
func TestSoundnessBudgetWeightAbove63BitsRefusesHonestBallots(t *testing.T) {
	c := qt.New(t)
	soundnessBuild(t)
	prod := loadR1CS(t, build.prodR1CS)
	weights, costs := budgetVectors()
	var refused []string
	for _, weight := range weights {
		for _, cost := range costs {
			name := fmt.Sprintf("weight=%s cost=%s", weight, cost)
			// Every vector is an honest ballot: cost <= weight.
			c.Assert(cost.Cmp(weight) <= 0, qt.IsTrue)
			b := budgetCase(t, cost, weight)
			w, err := calcWitness(t, build.prodWasm, b.inputs())
			if err != nil {
				// The calculator's refusal matches the constraint analysis:
				// the 90-bit decomposition has no solution.
				c.Assert(budgetAccepts(cost, weight), qt.IsFalse, qt.Commentf("%s: %v", name, err))
				refused = append(refused, name)
				continue
			}
			c.Assert(budgetAccepts(cost, weight), qt.IsTrue, qt.Commentf(name))
			c.Assert(witnessSatisfies(t, prod, w), qt.IsTrue, qt.Commentf(name))
		}
	}
	// weight 2^64, cost 2^64 (one field of 2^32 with exponent 2): the upper
	// bound holds, the lower bound's decomposition does not.
	weight := bigPow2(64)
	b := newBallotCase(t, simpleMode(1, 1<<48-1, 0, 2), []*big.Int{bigPow2(32)}, weight)
	if _, err := calcWitness(t, build.prodWasm, b.inputs()); err != nil {
		c.Assert(budgetAccepts(bigPow2(64), weight), qt.IsFalse)
		c.Assert(comparatorWindow(bigPow2(64), weight), qt.IsTrue)
		refused = append(refused, "weight=2^64 cost=2^64")
	}
	t.Logf("honest ballots refused: %v", refused)
	c.Assert(refused, qt.HasLen, 0, qt.Commentf("honest ballots with no satisfying witness"))
}

// TestSoundnessBudgetWeightWindowNeverExceedsWeight: whatever the weight,
// no witness carries a cost above it. Checked on the constraint arithmetic
// for every cost near the window edges, and on the calculator for
// cost = weight + 1.
func TestSoundnessBudgetWeightWindowNeverExceedsWeight(t *testing.T) {
	c := qt.New(t)
	soundnessBuild(t)
	prod := loadR1CS(t, build.prodR1CS)
	weights, _ := budgetVectors()
	for _, weight := range weights {
		// Below the window, inside it, above it: accepted iff inside, <= weight
		// and (lower bound) < 2^89.
		lo := new(big.Int).Sub(weight, bigPow2(valueSumCmpBits))
		lo.Add(lo, big.NewInt(1))
		for _, cost := range []*big.Int{
			new(big.Int).Sub(lo, big.NewInt(1)), lo, weight,
			new(big.Int).Add(weight, big.NewInt(1)),
			new(big.Int).Add(weight, bigPow2(63)),
			new(big.Int).Sub(bn254r, big.NewInt(1)),
		} {
			want := cost.Sign() >= 0 && cost.Cmp(lo) >= 0 && cost.Cmp(weight) <= 0 && cost.Cmp(bigPow2(valueSumCmpBits)) < 0
			c.Assert(budgetAccepts(cost, weight), qt.Equals, want, qt.Commentf("weight=%s cost=%s", weight, cost))
		}
	}
	// weight 2^63 + 5, cost 2^63 + 6: refused by the calculator and by the arithmetic.
	weight := new(big.Int).Add(bigPow2(63), big.NewInt(5))
	cost := new(big.Int).Add(weight, big.NewInt(1))
	b := newBallotCase(t, simpleMode(1, 1<<48-1, 0, 1), []*big.Int{cost}, weight)
	_, err := calcWitness(t, build.prodWasm, b.inputs())
	c.Assert(err, qt.IsNotNil)
	// Small weights: cost = weight accepted, weight + 1 refused.
	for _, weight := range ints(0, 1, 7, 1<<40) {
		ok := newBallotCase(t, simpleMode(1, 1<<48-1, 0, 1), []*big.Int{weight}, weight)
		w, err := calcWitness(t, build.prodWasm, ok.inputs())
		c.Assert(err, qt.IsNil)
		c.Assert(witnessSatisfies(t, prod, w), qt.IsTrue)
		over := newBallotCase(t, simpleMode(1, 1<<48-1, 0, 1), []*big.Int{new(big.Int).Add(weight, big.NewInt(1))}, weight)
		_, err = calcWitness(t, build.prodWasm, over.inputs())
		c.Assert(err, qt.IsNotNil)
	}
}

// TestSoundnessBudgetSumBoundsAreWindows: with maxValueSum set, the two
// comparators force the field value of the cost sum into
// [minValueSum, maxValueSum] exactly, and maxValueSum/minValueSum at or
// above 2^63 cannot be expressed: the packed layout gives them 63 bits and
// the contract refuses larger ones, so the only wide operand is the weight.
func TestSoundnessBudgetSumBoundsAreWindows(t *testing.T) {
	c := qt.New(t)
	soundnessBuild(t)
	prod := loadR1CS(t, build.prodR1CS)
	maxSum := uint64(1<<63 - 1)
	mode := ballotMode{NumFields: 2, GroupSize: 2, CostExponent: 1, MaxValue: 1<<48 - 1, MaxValueSum: maxSum, MinValueSum: 7}
	for _, tc := range []struct {
		fields []*big.Int
		ok     bool
	}{
		{ints(7, 0), true},
		{ints(6, 0), false},
		{ints(1<<48-1, 1<<48-1), true},
		{ints(0, 0), false},
	} {
		b := newBallotCase(t, mode, tc.fields, big.NewInt(0))
		w, err := calcWitness(t, build.prodWasm, b.inputs())
		c.Assert(err == nil, qt.Equals, tc.ok, qt.Commentf("fields %v: %v", tc.fields, err))
		if err == nil {
			c.Assert(witnessSatisfies(t, prod, w), qt.IsTrue)
		}
	}
	// A maxValueSum of 2^63 does not fit its 63-bit window: packed, its bit
	// lands on minValueSum bit 0, and the circuit reads maxValueSum = 0 (the
	// weight) and minValueSum = 1. The contract's packBallotMode refuses it
	// (GenesisLib.sol), so this only documents the layout.
	bleed := new(big.Int).SetUint64(uint64(mode.NumFields))
	bleed.Or(bleed, new(big.Int).Lsh(big.NewInt(int64(mode.GroupSize)), 8))
	bleed.Or(bleed, new(big.Int).Lsh(big.NewInt(1), 17))
	bleed.Or(bleed, new(big.Int).Lsh(new(big.Int).SetUint64(mode.MaxValue), 25))
	bleed.Or(bleed, new(big.Int).Lsh(bigPow2(63), 121))
	decoded := ballotMode{NumFields: 2, GroupSize: 2, CostExponent: 1, MaxValue: 1<<48 - 1, MaxValueSum: 0, MinValueSum: 1}
	c.Assert(bleed.Cmp(decoded.pack()), qt.Equals, 0)
}
