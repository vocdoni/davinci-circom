package test

import (
	"math/big"
	"testing"

	qt "github.com/frankban/quicktest"
	"github.com/vocdoni/davinci-circom/test/testutils"
	spectestutil "github.com/vocdoni/davinci-node/spec/testutil"
)

// circuitUnpack decodes a packed ballot mode the way UnpackBallotMode does
// (ballot_protocol.circom), which is also GenesisLib.packBallotMode and the
// SDK's packBallotMode.
func circuitUnpack(packed *big.Int) ballotMode {
	get := func(off, n uint) uint64 {
		v := new(big.Int).Rsh(packed, off)
		v.And(v, new(big.Int).Sub(bigPow2(n), big.NewInt(1)))
		return v.Uint64()
	}
	return ballotMode{
		NumFields:    uint8(get(0, 8)),
		GroupSize:    uint8(get(8, 8)),
		UniqueValues: get(16, 1) == 1,
		CostExponent: uint8(get(17, 8)),
		MaxValue:     get(25, 48),
		MinValue:     get(73, 48),
		MaxValueSum:  get(121, 63),
		MinValueSum:  get(184, 63),
	}
}

// TestSoundnessPackedLayoutRoundTrip pins the packed layout the circuit
// decodes against the one the contract and the SDK write, with every field
// at its maximum, and checks the packed value stays below 2^247 (the width
// of the circuit's Num2Bits, which makes the decomposition unique).
func TestSoundnessPackedLayoutRoundTrip(t *testing.T) {
	c := qt.New(t)
	full := ballotMode{NumFields: 255, GroupSize: 255, UniqueValues: true, CostExponent: 255, MaxValue: 1<<48 - 1, MinValue: 1<<48 - 1, MaxValueSum: 1<<63 - 1, MinValueSum: 1<<63 - 1}
	packed := full.pack()
	c.Assert(packed.BitLen(), qt.Equals, 247)
	c.Assert(circuitUnpack(packed), qt.DeepEquals, full)
	one := ballotMode{NumFields: 3, GroupSize: 1, CostExponent: 2, MaxValue: 5, MinValue: 1, MaxValueSum: 75, MinValueSum: 3}
	c.Assert(circuitUnpack(one.pack()), qt.DeepEquals, one)
}

// TestSoundnessTestVectorsUseCircuitLayout: the ballot vectors behind
// TestBallotProof must pack the ballot mode the way the circuit unpacks it.
// The pinned davinci-node/spec release packs a costFromWeight bit at 17 and
// shifts every later field by one, so the vectors prove a different mode
// from the one they claim (cost exponent 4 instead of 2, maxValue 32 instead
// of 16, ...), and only pass because that mode happens to admit the vector.
// BUG: testutils.BuildBallotVectors packs the ballot mode with spec.BallotMode.Pack, whose layout is not the circuit's.
func TestSoundnessTestVectorsUseCircuitLayout(t *testing.T) {
	c := qt.New(t)
	vectors, err := testutils.BuildBallotVectors()
	c.Assert(err, qt.IsNil)
	bm := spectestutil.FixedBallotMode()
	want := ballotMode{
		NumFields:    bm.NumFields,
		GroupSize:    bm.GroupSize,
		UniqueValues: bm.UniqueValues,
		CostExponent: bm.CostExponent,
		MaxValue:     bm.MaxValue,
		MinValue:     bm.MinValue,
		MaxValueSum:  bm.MaxValueSum,
		MinValueSum:  bm.MinValueSum,
	}
	got := circuitUnpack(vectors.PackedBallot)
	c.Assert(got, qt.DeepEquals, want)
}
