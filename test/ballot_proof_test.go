package test

import (
	"encoding/json"
	"fmt"
	"math/big"
	"os"
	"testing"

	qt "github.com/frankban/quicktest"
	"github.com/vocdoni/davinci-circom/circom2gnark"
	"github.com/vocdoni/davinci-circom/test/testutils"
)

func TestBallotProof(t *testing.T) {
	c := qt.New(t)
	vectors, err := testutils.BuildBallotVectors()
	c.Assert(err, qt.IsNil)

	inputBytes, err := json.MarshalIndent(vectors.InputsMap(), "", "  ")
	c.Assert(err, qt.IsNil)
	if persist && testID != "" {
		if outPath == "" {
			outPath = "../artifacts"
		}
		_ = os.MkdirAll(outPath, 0o755)
		_ = os.WriteFile(fmt.Sprintf("%s/%s_input.json", outPath, testID), inputBytes, 0o644)
	}

	// Get artifact paths
	wasmPath, err := testutils.GetArtifactPath(testutils.BallotProofWasm)
	c.Assert(err, qt.IsNil)
	zkeyPath, err := testutils.GetArtifactPath(testutils.BallotProofZkey)
	c.Assert(err, qt.IsNil)
	vkeyPath, err := testutils.GetArtifactPath(testutils.BallotProofVkey)
	c.Assert(err, qt.IsNil)

	// Generate proof
	proof, publicSignals, err := testutils.CompileAndGenerateProof(
		inputBytes,
		wasmPath,
		zkeyPath,
	)
	c.Assert(err, qt.IsNil)

	if persist && testID != "" {
		_ = os.WriteFile(fmt.Sprintf("%s/%s_proof.json", outPath, testID), []byte(proof), 0o644)
		_ = os.WriteFile(fmt.Sprintf("%s/%s_public.json", outPath, testID), []byte(publicSignals), 0o644)
	}

	// Verify proof
	vkey, err := os.ReadFile(vkeyPath)
	c.Assert(err, qt.IsNil)

	err = testutils.VerifyProof(proof, publicSignals, vkey)
	c.Assert(err, qt.IsNil)

	// The public signals are the 71 circuit inputs in layout order.
	var pubs []string
	c.Assert(json.Unmarshal([]byte(publicSignals), &pubs), qt.IsNil)
	c.Assert(pubs, qt.DeepEquals, vectors.PublicSignals())

	// Changing any single public signal breaks the proof.
	for i := range pubs {
		bad := append([]string(nil), pubs...)
		v, _ := new(big.Int).SetString(bad[i], 10)
		bad[i] = v.Add(v, big.NewInt(1)).String()
		ok, err := circom2gnark.VerifyCircomProofBN254(vkey, proof, bad)
		c.Assert(err == nil && ok, qt.IsFalse, qt.Commentf("public signal %d changed", i))
	}
}
