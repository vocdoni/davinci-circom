package test

import (
	"fmt"
	"math/big"
	"testing"

	"github.com/consensys/gnark-crypto/ecc/bn254/twistededwards"
	qt "github.com/frankban/quicktest"
)

// Attacks on the remaining constraint groups. Each case states what the
// constraints enforce; "refused" means the calculator refuses the input and
// the analysis in the comment says why no other witness exists.

// expectCalc runs the calculator and checks acceptance; accepted witnesses
// are verified on the ceremony r1cs.
func expectCalc(t *testing.T, b *ballotCase, accept bool, why string) []*big.Int {
	t.Helper()
	prod := loadR1CS(t, build.prodR1CS)
	w, err := calcWitness(t, build.prodWasm, b.inputs())
	if accept {
		if err != nil {
			t.Fatalf("%s: refused: %v", why, err)
		}
		if !witnessSatisfies(t, prod, w) {
			t.Fatalf("%s: witness does not satisfy the r1cs", why)
		}
		return w
	}
	if err == nil {
		t.Fatalf("%s: accepted", why)
	}
	t.Logf("%s: %v", why, err)
	return nil
}

// TestSoundnessFieldBoundsHeld: active fields are forced into [minValue,
// maxValue] by the two 49-bit comparators (ArrayInBounds). A field is an
// arbitrary field element, but GreaterThan(48)(arr, max) needs
// max + 2^48 - arr in [2^48, 2^49) and LessThan(48)(arr, min) needs
// arr + 2^48 - min in [2^48, 2^49): together arr is an integer in
// [min, max], and p - t ("negative" values) fail the second one for any
// t >= 1. Every field, active or padding, is also below 2^48 through the
// Num2Bits(48) that encodes the message in ElGamal.
func TestSoundnessFieldBoundsHeld(t *testing.T) {
	soundnessBuild(t)
	mode := ballotMode{NumFields: 3, GroupSize: 3, CostExponent: 1, MinValue: 2, MaxValue: 10, MaxValueSum: 100}
	one := big.NewInt(1)
	pm1 := new(big.Int).Sub(bn254r, one)
	expectCalc(t, newBallotCase(t, mode, ints(10, 2, 7), one), true, "in range")
	expectCalc(t, newBallotCase(t, mode, ints(11, 2, 2), one), false, "max + 1")
	expectCalc(t, newBallotCase(t, mode, ints(1, 2, 2), one), false, "min - 1")
	expectCalc(t, newBallotCase(t, mode, []*big.Int{pm1, big.NewInt(2), big.NewInt(2)}, one), false, "p - 1 as a field value")
	expectCalc(t, newBallotCase(t, mode, []*big.Int{new(big.Int).Sub(bn254r, big.NewInt(3)), big.NewInt(2), big.NewInt(2)}, one), false, "p - 3 as a field value")
	expectCalc(t, newBallotCase(t, mode, []*big.Int{bigPow2(48), big.NewInt(2), big.NewInt(2)}, one), false, "2^48 in an active slot")
	// Padding slots are not range-checked against the mode but are < 2^48.
	expectCalc(t, newBallotCase(t, mode, []*big.Int{big.NewInt(2), big.NewInt(2), big.NewInt(2), new(big.Int).Sub(bigPow2(48), one)}, one), true, "2^48 - 1 in a padding slot")
	expectCalc(t, newBallotCase(t, mode, []*big.Int{big.NewInt(2), big.NewInt(2), big.NewInt(2), bigPow2(48)}, one), false, "2^48 in a padding slot")
	// Sum bounds against the field values, exponent 2.
	quad := ballotMode{NumFields: 3, GroupSize: 3, CostExponent: 2, MaxValue: 4, MaxValueSum: 12, MinValueSum: 5}
	expectCalc(t, newBallotCase(t, quad, ints(2, 2, 2), one), true, "cost 12 of 12")
	expectCalc(t, newBallotCase(t, quad, ints(3, 2, 0), one), false, "cost 13 of 12")
	expectCalc(t, newBallotCase(t, quad, ints(2, 0, 0), one), false, "cost 4 below min sum 5")
}

// TestSoundnessModeChecksHeld: group size, uniqueness, min > max, numFields
// above the capacity, the packed width and a zero cost exponent.
func TestSoundnessModeChecksHeld(t *testing.T) {
	c := qt.New(t)
	soundnessBuild(t)
	one := big.NewInt(1)
	base := ballotMode{NumFields: 3, GroupSize: 3, CostExponent: 1, MaxValue: 10, MaxValueSum: 100}

	gs := base
	gs.GroupSize = 4
	expectCalc(t, newBallotCase(t, gs, ints(1, 2, 3), one), false, "group_size 4 > num_fields 3")

	uniq := base
	uniq.UniqueValues = true
	expectCalc(t, newBallotCase(t, uniq, ints(1, 2, 3), one), true, "unique values")
	expectCalc(t, newBallotCase(t, uniq, ints(3, 3, 1), one), false, "duplicate under unique_values")
	expectCalc(t, newBallotCase(t, uniq, ints(0, 0, 1), one), false, "duplicate zeros under unique_values")
	// Padding slots are outside the uniqueness check even when equal to active ones.
	expectCalc(t, newBallotCase(t, uniq, ints(1, 2, 3, 3), one), true, "padding slot equal to an active one")

	inverted := base
	inverted.MinValue, inverted.MaxValue = 5, 4
	expectCalc(t, newBallotCase(t, inverted, ints(4, 4, 4), one), false, "min > max, value = max")
	expectCalc(t, newBallotCase(t, inverted, ints(5, 5, 5), one), false, "min > max, value = min")

	// numFields 17: MaskGenerator's assert() is not a constraint, but
	// valid_fields === num_fields cannot hold with 16 slots (the mask is all
	// ones and the sum of 16 bits is at most 16).
	wide := base
	wide.NumFields, wide.GroupSize = 17, 1
	expectCalc(t, newBallotCase(t, wide, ints(1, 2, 3), one), false, "num_fields 17")
	wide.NumFields = 255
	expectCalc(t, newBallotCase(t, wide, ints(1, 2, 3), one), false, "num_fields 255")

	// A packed mode at or above 2^247 has no 247-bit decomposition.
	b := newBallotCase(t, base, ints(1, 2, 3), one)
	b.packed = new(big.Int).Add(b.packed, bigPow2(247))
	expectCalc(t, b, false, "packed_ballot_mode + 2^247")

	// cost_exponent 0: every active field costs 1 (0^0 = 1 in Pow), so the
	// budget check only counts fields. The contract accepts the exponent;
	// it is a mode-level oddity, not a circuit defect.
	zero := base
	zero.CostExponent, zero.MaxValueSum = 0, 3
	expectCalc(t, newBallotCase(t, zero, ints(10, 10, 10), one), true, "exponent 0, budget 3 = num_fields")
	zero.MaxValueSum = 2
	expectCalc(t, newBallotCase(t, zero, ints(0, 0, 0), one), false, "exponent 0, budget 2 < num_fields")

	// numFields 0: no active field, every check is vacuous and the ballot
	// proves. The contract (numFields == 0 reverts) and the guest (4.3.6)
	// refuse the mode.
	empty := ballotMode{NumFields: 0, GroupSize: 0, CostExponent: 1, MaxValue: 10, MaxValueSum: 100}
	w := expectCalc(t, newBallotCase(t, empty, nil, one), true, "num_fields 0")
	c.Assert(w, qt.Not(qt.IsNil))
}

// TestSoundnessInputsTheCircuitLeavesToTheGuest documents the public
// inputs the circuit does not constrain on its own, each of which the
// zkVM guest derives from data it has verified (publics.rs):
//   - weight, when maxValueSum != 0 (the Mux output ignores it);
//   - the cipherfields of padding slots (the comparison is masked);
//   - the width of address and process_id (hashed as field elements).
func TestSoundnessInputsTheCircuitLeavesToTheGuest(t *testing.T) {
	c := qt.New(t)
	soundnessBuild(t)
	prod := loadR1CS(t, build.prodR1CS)
	prodSym := loadSym(t, build.prodSym)
	one := big.NewInt(1)
	mode := ballotMode{NumFields: 3, GroupSize: 3, CostExponent: 1, MaxValue: 10, MaxValueSum: 100}

	// weight: any value, by editing the public wire of a valid witness.
	w := expectCalc(t, newBallotCase(t, mode, ints(1, 2, 3), one), true, "honest")
	for _, v := range []*big.Int{big.NewInt(0), bigPow2(88), new(big.Int).Sub(bn254r, one)} {
		edited := append([]*big.Int(nil), w...)
		edited[prodSym["main.weight"]] = v
		c.Assert(witnessSatisfies(t, prod, edited), qt.IsTrue, qt.Commentf("weight %s", v))
	}
	// weight matters as soon as maxValueSum is 0.
	fromWeight := mode
	fromWeight.MaxValueSum = 0
	w = expectCalc(t, newBallotCase(t, fromWeight, ints(1, 2, 3), big.NewInt(6)), true, "cost 6, weight 6")
	edited := append([]*big.Int(nil), w...)
	edited[prodSym["main.weight"]] = big.NewInt(5)
	c.Assert(witnessSatisfies(t, prod, edited), qt.IsFalse)

	// Padding cipherfields: anything, even off the curve.
	b := newBallotCase(t, mode, ints(1, 2, 3), one)
	b.cipherfields[3] = [2][2]*big.Int{{big.NewInt(7), big.NewInt(8)}, {big.NewInt(9), new(big.Int).Sub(bn254r, one)}}
	b.cipherfields[15] = [2][2]*big.Int{{big.NewInt(1), big.NewInt(1)}, {big.NewInt(0), big.NewInt(0)}}
	expectCalc(t, b, true, "garbage in padding cipherfields")
	// An active cipherfield must match exactly.
	b = newBallotCase(t, mode, ints(1, 2, 3), one)
	b.cipherfields[2][1][0] = new(big.Int).Add(b.cipherfields[2][1][0], one)
	expectCalc(t, b, false, "active cipherfield c2.x + 1")
	b = newBallotCase(t, mode, ints(1, 2, 3), one)
	b.cipherfields[0] = [2][2]*big.Int{{big.NewInt(0), big.NewInt(1)}, {big.NewInt(0), big.NewInt(1)}}
	expectCalc(t, b, false, "identity in an active slot")

	// address and process_id of any width.
	b = newBallotCase(t, mode, ints(1, 2, 3), one)
	b.address = new(big.Int).Sub(bn254r, one)
	b.processID = bigPow2(200)
	b.voteID = mustVoteID(t, b)
	expectCalc(t, b, true, "address p - 1, process id 2^200")

	// vote id: only the derived value, in the namespace.
	b = newBallotCase(t, mode, ints(1, 2, 3), one)
	b.voteID = new(big.Int).Sub(b.voteID, bigPow2(63))
	expectCalc(t, b, false, "vote id without the namespace bit")
	b = newBallotCase(t, mode, ints(1, 2, 3), one)
	b.voteID = new(big.Int).Add(b.voteID, one)
	expectCalc(t, b, false, "vote id + 1")

	// k extremes.
	for _, k := range []*big.Int{big.NewInt(0), big.NewInt(1), new(big.Int).Sub(bn254r, one)} {
		b = newBallotCase(t, mode, ints(1, 2, 3), one)
		b.setK(t, k)
		expectCalc(t, b, true, fmt.Sprintf("k = %s", k))
	}
}

// TestSoundnessEncryptionKeyChecksHeld: the shared key must be on the
// curve, in the prime-order subgroup and not the identity. The order-2
// point (0, -1) and a point of the cofactor coset (G + (0, -1)) are
// refused; so are the identity and an off-curve point.
func TestSoundnessEncryptionKeyChecksHeld(t *testing.T) {
	soundnessBuild(t)
	one := big.NewInt(1)
	mode := ballotMode{NumFields: 1, GroupSize: 1, CostExponent: 1, MaxValue: 10, MaxValueSum: 100}
	pm1 := new(big.Int).Sub(bn254r, one)

	curve := twistededwards.GetEdwardsCurve()
	var t2 twistededwards.PointAffine
	t2.X.SetZero()
	t2.Y.SetBigInt(pm1) // (0, -1): order 2 in both coordinate forms
	var coset twistededwards.PointAffine
	coset.Add(&curve.Base, &t2)
	cx, cy := pointToTE(coset)
	var l twistededwards.PointAffine
	l.ScalarMultiplication(&coset, babyJubOrder)
	if l.IsZero() {
		t.Fatal("G + (0,-1) is in the prime subgroup")
	}

	for _, tc := range []struct {
		name string
		x, y *big.Int
	}{
		{"identity (0, 1)", big.NewInt(0), big.NewInt(1)},
		{"order-2 point (0, -1)", big.NewInt(0), pm1},
		{"cofactor coset G + (0, -1)", cx, cy},
		{"off-curve (1, 1)", big.NewInt(1), big.NewInt(1)},
	} {
		b := newBallotCase(t, mode, ints(3), one)
		b.pubX, b.pubY = tc.x, tc.y
		b.recomputeCiphertexts(t)
		expectCalc(t, b, false, tc.name)
	}
}
