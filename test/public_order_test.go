package test

import (
	"bufio"
	"fmt"
	"os"
	"strings"
	"testing"

	qt "github.com/frankban/quicktest"
	"github.com/vocdoni/davinci-circom/test/testutils"
)

// ballotPublicOrder is the public-input layout every implementation mirrors
// (rust-sdk, go-sdk, the zkVM guest, the TS SDK).
func ballotPublicOrder() []string {
	names := []string{
		"main.address",
		"main.vote_id",
		"main.process_id",
		"main.packed_ballot_mode",
		"main.encryption_pubkey[0]",
		"main.encryption_pubkey[1]",
		"main.weight",
	}
	for f := range 16 {
		for c := range 2 {
			for xy := range 2 {
				names = append(names, fmt.Sprintf("main.cipherfields[%d][%d][%d]", f, c, xy))
			}
		}
	}
	return names
}

// TestBallotPublicSignalOrder pins the public signals of the compiled circuit:
// witness indices 1..71 of ballot_proof.sym (index 0 is the constant one).
func TestBallotPublicSignalOrder(t *testing.T) {
	c := qt.New(t)
	symPath, err := testutils.GetArtifactPath("ballot_proof.sym")
	c.Assert(err, qt.IsNil)
	f, err := os.Open(symPath)
	c.Assert(err, qt.IsNil, qt.Commentf("run make prepare first"))
	defer func() { _ = f.Close() }()

	want := ballotPublicOrder()
	c.Assert(want, qt.HasLen, 71)
	got := make([]string, len(want))
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		// labelIdx,witnessIdx,componentIdx,name
		parts := strings.SplitN(sc.Text(), ",", 4)
		if len(parts) != 4 {
			continue
		}
		var w int
		if _, err := fmt.Sscan(parts[1], &w); err != nil || w < 1 || w > len(want) {
			continue
		}
		got[w-1] = parts[3]
	}
	c.Assert(sc.Err(), qt.IsNil)
	c.Assert(got, qt.DeepEquals, want)
}
