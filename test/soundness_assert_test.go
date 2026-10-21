package test

import (
	"fmt"
	"math/big"
	"testing"

	qt "github.com/frankban/quicktest"
)

// TestSoundnessAssertIsNotAConstraint: circom's assert() only stops the
// witness calculator. MaskGenerator (lib/utils.circom:68-71) asserts
// num_fields <= 16 that way; compiled with and without the assert the
// template has the same wires and constraints, and a witness for
// num_fields = 17 computed without the assert satisfies the asserted r1cs.
// The ballot circuit does not rely on it: valid_fields === num_fields
// (ballot_proof.circom:77) refuses num_fields > 16 on its own
// (TestSoundnessModeChecksHeld).
func TestSoundnessAssertIsNotAConstraint(t *testing.T) {
	c := qt.New(t)
	withR1CS, withSym, withWasm := compileTestCircuit(t, "soundness_assert_with")
	woR1CS, woSym, woWasm := compileTestCircuit(t, "soundness_assert_without")
	with := loadR1CS(t, withR1CS)
	wo := loadR1CS(t, woR1CS)
	c.Assert(len(with.constraints), qt.Equals, len(wo.constraints))
	c.Assert(with.nWires, qt.Equals, wo.nWires)

	_, err := calcWitness(t, withWasm, map[string]any{"in": "17"})
	c.Assert(err, qt.IsNotNil)
	w, err := calcWitness(t, woWasm, map[string]any{"in": "17"})
	c.Assert(err, qt.IsNil)
	projected := projectWitness(t, loadSym(t, woSym), loadSym(t, withSym), with, w)
	c.Assert(witnessSatisfies(t, with, projected), qt.IsTrue)
	sym := loadSym(t, withSym)
	for i := 0; i < 16; i++ {
		c.Assert(getByName(t, sym, projected, fmt.Sprintf("main.out[%d]", i)).Cmp(big.NewInt(1)), qt.Equals, 0)
	}
	c.Assert(getByName(t, sym, projected, "main.control.out").Sign(), qt.Equals, 0)
}
