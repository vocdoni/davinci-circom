package test

import (
	"math/big"
	"testing"

	qt "github.com/frankban/quicktest"
)

// TestSoundnessToolingHonestBallot checks the tooling on an honest ballot:
// the calculator's witness satisfies the production r1cs (Go checker and
// snarkjs agree), the O0 witness projects onto the production wires and
// still satisfies it, and a single edited wire breaks it.
func TestSoundnessToolingHonestBallot(t *testing.T) {
	c := qt.New(t)
	soundnessBuild(t)
	prod := loadR1CS(t, build.prodR1CS)
	c.Assert(prod.nPubIn, qt.Equals, nPublic)
	c.Assert(prod.nWires, qt.Equals, 61076)
	c.Assert(len(prod.constraints), qt.Equals, 61232)

	mode := ballotMode{NumFields: 6, GroupSize: 2, CostExponent: 2, MaxValue: 16, MaxValueSum: 1280, MinValueSum: 6}
	b := newBallotCase(t, mode, ints(1, 2, 3, 4, 5, 6), big.NewInt(1))

	w, err := calcWitness(t, build.prodWasm, b.inputs())
	c.Assert(err, qt.IsNil)
	c.Assert(witnessSatisfies(t, prod, w), qt.IsTrue)
	ok, _ := snarkjsWtnsCheck(t, build.prodR1CS, w)
	c.Assert(ok, qt.IsTrue)

	// Public inputs sit at wires 1..71 in layout order.
	prodSym := loadSym(t, build.prodSym)
	c.Assert(prodSym["main.vote_id"], qt.Equals, 2)
	c.Assert(w[2].String(), qt.Equals, b.voteID.String())
	c.Assert(prodSym["main.weight"], qt.Equals, 7)

	// O0 witness projected by name satisfies the production r1cs too.
	o0 := loadR1CS(t, build.o0R1CS)
	o0Sym := loadSym(t, build.o0Sym)
	w0, err := calcWitness(t, build.o0Wasm, b.inputs())
	c.Assert(err, qt.IsNil)
	c.Assert(witnessSatisfies(t, o0, w0), qt.IsTrue)
	wp := projectWitness(t, o0Sym, prodSym, prod, w0)
	c.Assert(witnessSatisfies(t, prod, wp), qt.IsTrue)
	for i := 1; i <= nPublic; i++ {
		c.Assert(wp[i].Cmp(w[i]), qt.Equals, 0, qt.Commentf("public input %d", i))
	}

	// Editing one bit of the vote id without the rest breaks it.
	bad := append([]*big.Int(nil), w...)
	bad[2] = new(big.Int).Add(bad[2], big.NewInt(1))
	c.Assert(witnessSatisfies(t, prod, bad), qt.IsFalse)
}

// TestSoundnessSnarkjsCheckExitCode pins how snarkjs 0.7.6 `wtns check`
// reports a witness that violates the r1cs: "WITNESS IS NOT CORRECT" in the
// log and exit status 1 (an earlier note claimed it exits 0 either way; it
// does not, but the tests still read the log line, which cannot be lost by a
// shell pipe or a wrapper).
func TestSoundnessSnarkjsCheckExitCode(t *testing.T) {
	c := qt.New(t)
	soundnessBuild(t)
	prod := loadR1CS(t, build.prodR1CS)
	b := newBallotCase(t, simpleMode(1, 10, 100, 1), ints(3), big.NewInt(1))
	w, err := calcWitness(t, build.prodWasm, b.inputs())
	c.Assert(err, qt.IsNil)
	bad := append([]*big.Int(nil), w...)
	bad[1] = new(big.Int).Add(bad[1], big.NewInt(1)) // address
	c.Assert(witnessSatisfies(t, prod, bad), qt.IsFalse)
	ok, exit := snarkjsWtnsCheck(t, build.prodR1CS, bad)
	c.Assert(ok, qt.IsFalse)
	c.Assert(exit, qt.Equals, 1)
	ok, exit = snarkjsWtnsCheck(t, build.prodR1CS, w)
	c.Assert(ok, qt.IsTrue)
	c.Assert(exit, qt.Equals, 0)
}
