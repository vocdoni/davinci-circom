package test

import (
	"fmt"
	"math/big"
	"strings"
	"testing"

	qt "github.com/frankban/quicktest"
	spechash "github.com/vocdoni/davinci-node/spec/hash"
)

// Num2Bits(254) (circomlib bitify.circom) constrains 254 bits whose weighted
// sum equals the input in the field, nothing more. A value v below
// 2^254 - p therefore has a second decomposition, the bits of v + p. The
// vote-id hash (lib/vote_id.circom) goes through Num2Bits_strict, whose
// AliasCheck refuses that second decomposition; the per-field k
// (lib/elgamal.circom) keeps the plain Num2Bits(254) (out of scope: both
// ciphertexts decrypt to the same message). The tests below build the second
// witness by editing the O0 witness by signal name and check it on the
// ceremony r1cs.

// aliasBound is 2^254 - p: values below it have two 254-bit decompositions.
var aliasBound = new(big.Int).Sub(bigPow2(254), bn254r)

// TestSoundnessVoteIDHasTwoValuesPerK: the vote id is a function of
// (process_id, address, k). For a hash H below 2^254 - p, the bits of H + p
// would give a second vote id (the low 63 bits of H + p, plus 2^63); the
// edited witness carries them through the strict decomposition, with the
// AliasCheck comparator computed honestly for those bits, and breaks exactly
// one constraint: AliasCheck's.
func TestSoundnessVoteIDHasTwoValuesPerK(t *testing.T) {
	c := qt.New(t)
	soundnessBuild(t)
	prod := loadR1CS(t, build.prodR1CS)
	prodSym := loadSym(t, build.prodSym)
	o0 := loadR1CS(t, build.o0R1CS)
	o0Sym := loadSym(t, build.o0Sym)
	_, ccSymPath, ccWasm := compileTestCircuit(t, "soundness_compconstant")
	ccSym := loadSym(t, ccSymPath)
	mode := simpleMode(1, 10, 100, 1)

	var b *ballotCase
	var h *big.Int
	for try := 0; ; try++ {
		c.Assert(try < 64, qt.IsTrue, qt.Commentf("no aliasable hash in 64 tries"))
		b = newBallotCase(t, mode, ints(3), big.NewInt(1))
		var err error
		h, err = spechash.PoseidonHash(b.processID, b.address, b.k)
		c.Assert(err, qt.IsNil)
		if h.Cmp(aliasBound) < 0 {
			break
		}
	}
	w0, err := calcWitness(t, build.o0Wasm, b.inputs())
	c.Assert(err, qt.IsNil)
	c.Assert(getByName(t, o0Sym, w0, "main.voteIDChecker.hasher.out").Cmp(h), qt.Equals, 0)
	c.Assert(witnessSatisfies(t, o0, w0), qt.IsTrue)

	alias := new(big.Int).Add(h, bn254r)
	c.Assert(alias.BitLen() <= 254, qt.IsTrue)
	bits := bitsOf(alias, 254)
	const strict = "main.voteIDChecker.bits."
	res := new(big.Int)
	setByName(t, o0Sym, w0, "main.voteIDChecker.res[0]", res)
	for i := 0; i < 254; i++ {
		for _, name := range []string{"out", "n2b.out", "aliasCheck.in", "aliasCheck.compConstant.in"} {
			setByName(t, o0Sym, w0, fmt.Sprintf("%s%s[%d]", strict, name, i), bits[i])
		}
		if i < 63 {
			res = new(big.Int).Add(res, new(big.Int).Lsh(bits[i], uint(i)))
			setByName(t, o0Sym, w0, fmt.Sprintf("main.voteIDChecker.res[%d]", i+1), res)
		}
	}
	// AliasCheck's comparator, computed for the alias bits: it outputs 1.
	wcc, err := calcWitness(t, ccWasm, map[string]any{"in": bitStrings(bits)})
	c.Assert(err, qt.IsNil)
	c.Assert(getByName(t, ccSym, wcc, "main.out").Int64(), qt.Equals, int64(1))
	moved := 0
	for name, wire := range ccSym {
		if wire < 0 || strings.HasPrefix(name, "main.in[") {
			continue
		}
		setByName(t, o0Sym, w0, strict+"aliasCheck.compConstant."+strings.TrimPrefix(name, "main."), wcc[wire])
		moved++
	}
	c.Assert(moved > 250, qt.IsTrue, qt.Commentf("moved %d wires", moved))
	vid2 := new(big.Int).Add(res, bigPow2(63))
	setByName(t, o0Sym, w0, "main.voteIDChecker.vote_id", vid2)
	setByName(t, o0Sym, w0, "main.vote_id", vid2)

	c.Assert(vid2.Cmp(b.voteID), qt.Not(qt.Equals), 0)
	c.Assert(vid2.Cmp(bigPow2(63)) >= 0 && vid2.Cmp(bigPow2(64)) < 0, qt.IsTrue)
	// Every O0 constraint holds except AliasCheck's `compConstant.out === 0`.
	_, broken := checkR1CS(o0, w0)
	c.Assert(broken, qt.Equals, 1)
	w := projectWitness(t, o0Sym, prodSym, prod, w0)
	c.Assert(w[2].Cmp(vid2), qt.Equals, 0) // public input 1
	goOK := witnessSatisfies(t, prod, w)
	snarkOK, _ := snarkjsWtnsCheck(t, build.prodR1CS, w)
	c.Assert(goOK, qt.Equals, snarkOK)
	c.Assert(goOK, qt.IsFalse, qt.Commentf("vote id %s and %s both prove for the same (process, address, k)", b.voteID, vid2))
}

// TestSoundnessElGamalHasTwoCiphertextsPerK: the per-field randomness
// k_i = Poseidon(k_{i-1}) can be decomposed as k_i or k_i + p, which gives
// a second ciphertext ((k_i + p) G, m G + (k_i + p) P) for the same k and
// message. Both decrypt to m G, so the tally is unaffected; only the SDK's
// deterministic ciphertext for a k is not the only one the circuit accepts.
// Accepted: the 16 ElGamal decompositions stay non-strict (no security gain
// for 16 x ~300 constraints); this test pins that the alias proves.
func TestSoundnessElGamalHasTwoCiphertextsPerK(t *testing.T) {
	c := qt.New(t)
	soundnessBuild(t)
	prod := loadR1CS(t, build.prodR1CS)
	prodSym := loadSym(t, build.prodSym)
	o0 := loadR1CS(t, build.o0R1CS)
	o0Sym := loadSym(t, build.o0Sym)
	egSym := loadSym(t, build.elgamalSym)
	const f = 0
	mode := simpleMode(2, 10, 100, 1)

	var b *ballotCase
	for try := 0; ; try++ {
		c.Assert(try < 64, qt.IsTrue)
		b = newBallotCase(t, mode, ints(3, 4), big.NewInt(1))
		if b.ks[f+1].Cmp(aliasBound) < 0 {
			break
		}
	}
	w0, err := calcWitness(t, build.o0Wasm, b.inputs())
	c.Assert(err, qt.IsNil)

	alias := new(big.Int).Add(b.ks[f+1], bn254r)
	wEg, err := calcWitness(t, build.elgamalWasm, map[string]any{
		"encryption_pubkey": []string{b.pubX.String(), b.pubY.String()},
		"msg":               b.fields[f].String(),
		"kbits":             bitStrings(bitsOf(alias, 254)),
	})
	c.Assert(err, qt.IsNil)

	// Transplant by name: the scalar multiplications and the addition take
	// the test circuit's values; the message encoding must already agree.
	prefix := fmt.Sprintf("main.ballotCipher.ciphers[%d].", f)
	moved := 0
	for name, wire := range egSym {
		suffix := strings.TrimPrefix(name, "main.")
		switch {
		case strings.HasPrefix(suffix, "kbits["):
			setByName(t, o0Sym, w0, prefix+"kBits.out["+strings.TrimPrefix(suffix, "kbits["), wEg[wire])
			moved++
		case strings.HasPrefix(suffix, "c1Point."), strings.HasPrefix(suffix, "sPoint."), strings.HasPrefix(suffix, "c2Point."),
			strings.HasPrefix(suffix, "c1["), strings.HasPrefix(suffix, "c2["):
			setByName(t, o0Sym, w0, prefix+suffix, wEg[wire])
			moved++
		case strings.HasPrefix(suffix, "messageBits."), strings.HasPrefix(suffix, "messagePoint."), suffix == "msg":
			c.Assert(getByName(t, o0Sym, w0, prefix+suffix).Cmp(wEg[wire]), qt.Equals, 0, qt.Commentf(name))
		}
	}
	c.Assert(moved > 17000, qt.IsTrue, qt.Commentf("moved %d wires", moved))

	alt := [2][2]*big.Int{
		{getByName(t, o0Sym, w0, prefix+"c1[0]"), getByName(t, o0Sym, w0, prefix+"c1[1]")},
		{getByName(t, o0Sym, w0, prefix+"c2[0]"), getByName(t, o0Sym, w0, prefix+"c2[1]")},
	}
	for a := 0; a < 2; a++ {
		for x := 0; x < 2; x++ {
			v := alt[a][x]
			for _, name := range []string{
				fmt.Sprintf("main.cipherfields[%d][%d][%d]", f, a, x),
				fmt.Sprintf("main.ballotCipher.cipherfields[%d][%d][%d]", f, a, x),
				fmt.Sprintf("main.ballotCipher.fieldComparator[%d].expected[%d][%d]", f, a, x),
				fmt.Sprintf("main.ballotCipher.fieldComparator[%d].computed[%d][%d]", f, a, x),
			} {
				setByName(t, o0Sym, w0, name, v)
			}
			cmp := [2][2]string{{"iseqC1X", "iseqC1Y"}, {"iseqC2X", "iseqC2Y"}}[a][x]
			setByName(t, o0Sym, w0, fmt.Sprintf("main.ballotCipher.fieldComparator[%d].%s.in[0]", f, cmp), v)
			setByName(t, o0Sym, w0, fmt.Sprintf("main.ballotCipher.fieldComparator[%d].%s.in[1]", f, cmp), v)
		}
	}

	orig := b.cipherfields[f]
	c.Assert(alt[0][0].Cmp(orig[0][0]) != 0 || alt[0][1].Cmp(orig[0][1]) != 0, qt.IsTrue, qt.Commentf("c1 unchanged"))
	// alt c1 = (k_i + p) G, as a group element.
	x, y := scalarBaseTE(alias)
	c.Assert(alt[0][0].Cmp(x), qt.Equals, 0)
	c.Assert(alt[0][1].Cmp(y), qt.Equals, 0)
	// Both ciphertexts decrypt to m G.
	mx, my := scalarBaseTE(b.fields[f])
	for _, ct := range [][2][2]*big.Int{orig, alt} {
		dx, dy := elgamalDecrypt(b.sk, ct)
		c.Assert(dx.Cmp(mx), qt.Equals, 0)
		c.Assert(dy.Cmp(my), qt.Equals, 0)
	}

	c.Assert(witnessSatisfies(t, o0, w0), qt.IsTrue)
	w := projectWitness(t, o0Sym, prodSym, prod, w0)
	goOK := witnessSatisfies(t, prod, w)
	snarkOK, _ := snarkjsWtnsCheck(t, build.prodR1CS, w)
	c.Assert(goOK, qt.Equals, snarkOK)
	c.Assert(goOK, qt.IsTrue, qt.Commentf("the k_i + p ciphertext no longer proves: update this pin"))
}

// TestSoundnessSubgroupOrderBitsHaveNoAlias: BabyCheckPrimeSubgroup feeds
// the bits of the subgroup order l to its scalar multiplication as
// constants, so there is no decomposition for a prover to choose at any
// width. (A 254-bit decomposition of l would also admit l + p, and
// (l + p) P = p P holds for the order-2 point (0, -1), since l + p is even.)
// The O0 circuit has no decomposition component, an honest witness carries
// the bits of l, and the production r1cs has no wire for any of them.
func TestSoundnessSubgroupOrderBitsHaveNoAlias(t *testing.T) {
	c := qt.New(t)
	sum := new(big.Int).Add(babyJubOrder, bn254r)
	c.Assert(sum.BitLen(), qt.Equals, 254)
	c.Assert(sum.Bit(0), qt.Equals, uint(0)) // l + p is even
	c.Assert(babyJubOrder.BitLen() <= 253, qt.IsTrue)

	soundnessBuild(t)
	prodSym := loadSym(t, build.prodSym)
	o0Sym := loadSym(t, build.o0Sym)
	const check = "main.ballotCipher.pubkeySubgroupCheck."
	for name := range o0Sym {
		c.Assert(strings.HasPrefix(name, check+"orderBits"), qt.IsFalse, qt.Commentf("%s: l is decomposed in-circuit", name))
	}
	b := newBallotCase(t, simpleMode(1, 10, 100, 1), ints(3), big.NewInt(1))
	w0, err := calcWitness(t, build.o0Wasm, b.inputs())
	c.Assert(err, qt.IsNil)
	for i := 0; i < 253; i++ {
		name := fmt.Sprintf("%ssubgroupMul.e[%d]", check, i)
		c.Assert(getByName(t, o0Sym, w0, name).Uint64(), qt.Equals, uint64(babyJubOrder.Bit(i)), qt.Commentf(name))
		wire, ok := prodSym[name]
		c.Assert(ok, qt.IsTrue, qt.Commentf(name))
		c.Assert(wire, qt.Equals, -1, qt.Commentf("%s is a witness wire, not a constant", name))
	}
}
