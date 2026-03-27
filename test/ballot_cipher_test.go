package test

import (
	"encoding/json"
	"math/big"
	"os"
	"os/exec"
	"path/filepath"
	"testing"

	qt "github.com/frankban/quicktest"
	"github.com/vocdoni/davinci-circom/test/testutils"
	spechash "github.com/vocdoni/davinci-node/spec/hash"
	specutil "github.com/vocdoni/davinci-node/spec/util"
)

func TestBallotCipher(t *testing.T) {
	c := qt.New(t)
	wasmPath, zkeyPath, vkey := buildBallotCipherTestArtifacts(t)

	// encrypt ballot
	_, pubX, pubY := testutils.GenerateKeyPair()

	k, err := specutil.RandomK()
	c.Assert(err, qt.IsNil, qt.Commentf("Error generating random k"))

	// Circuit derives k_i = Poseidon(k_{i-1}) per field; we only have one field.
	ks, err := spechash.DerivePoseidonChain(k, 1)
	c.Assert(err, qt.IsNil, qt.Commentf("derive ks"))

	msg := big.NewInt(3)
	c1, c2 := testutils.Encrypt(msg, pubX, pubY, ks[1])
	inputs := map[string]any{
		"encryption_pubkey": []string{pubX.String(), pubY.String()},
		"k":                 k.String(),
		"msg":               msg.String(),
		"c1":                []string{c1[0].String(), c1[1].String()},
		"c2":                []string{c2[0].String(), c2[1].String()},
	}
	bInputs, _ := json.MarshalIndent(inputs, "  ", "  ")
	c.Log("Inputs:", string(bInputs))
	proofData, pubSignals, err := testutils.CompileAndGenerateProof(bInputs, wasmPath, zkeyPath)
	c.Assert(err, qt.IsNil, qt.Commentf("Error compiling and generating proof"))

	err = testutils.VerifyProof(proofData, pubSignals, vkey)
	c.Assert(err, qt.IsNil, qt.Commentf("Error verifying proof"))
	c.Log("Proof verified")
}

func buildBallotCipherTestArtifacts(t *testing.T) (string, string, []byte) {
	t.Helper()

	tempDir := t.TempDir()
	repoRoot, err := filepath.Abs("..")
	if err != nil {
		t.Fatal(err)
	}

	circomBin := filepath.Join(repoRoot, "deps", "circom")
	ptauFile := filepath.Join(repoRoot, "artifacts", "ptau_final.ptau")
	snarkjsPath := filepath.Join(repoRoot, "node_modules", ".bin", "snarkjs")

	cmd := exec.Command(circomBin,
		"test/ballot_cipher_test.circom",
		"--r1cs", "--wasm", "--sym",
		"-o", tempDir,
		"-l", "./circuits",
		"-l", "./node_modules",
	)
	cmd.Dir = repoRoot
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("compile ballot_cipher_test: %v\n%s", err, out)
	}

	r1csFile := filepath.Join(tempDir, "ballot_cipher_test.r1cs")
	zkeyFile := filepath.Join(tempDir, "ballot_cipher_test_pkey.zkey")
	vkeyFile := filepath.Join(tempDir, "ballot_cipher_test_vkey.json")
	wasmFile := filepath.Join(tempDir, "ballot_cipher_test_js", "ballot_cipher_test.wasm")

	cmd = exec.Command(snarkjsPath, "groth16", "setup", r1csFile, ptauFile, zkeyFile)
	cmd.Dir = repoRoot
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("setup ballot_cipher_test: %v\n%s", err, out)
	}

	cmd = exec.Command(snarkjsPath, "zkey", "export", "verificationkey", zkeyFile, vkeyFile)
	cmd.Dir = repoRoot
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("export ballot_cipher_test vkey: %v\n%s", err, out)
	}

	vkey, err := os.ReadFile(vkeyFile)
	if err != nil {
		t.Fatal(err)
	}
	return wasmFile, zkeyFile, vkey
}

func TestBallotCipherRejectsWrongSubgroupPubKey(t *testing.T) {
	c := qt.New(t)

	wasmPath, zkeyPath, vkey := buildBallotCipherTestArtifacts(t)

	// This point is on the BabyJubJub curve but outside the prime-order
	// subgroup. It was derived by sampling an on-curve point and checking that
	// [order]P != identity on the companion curve.
	pubX, _ := new(big.Int).SetString("12560539069453413007774288491703646385340365486963288216384006786834187334755", 10)
	pubY, _ := new(big.Int).SetString("6419179824265240134609548724973649318800064218296981359862664112982878269332", 10)

	k, err := specutil.RandomK()
	c.Assert(err, qt.IsNil, qt.Commentf("Error generating random k"))

	ks, err := spechash.DerivePoseidonChain(k, 1)
	c.Assert(err, qt.IsNil, qt.Commentf("derive ks"))

	msg := big.NewInt(3)
	c1, c2 := testutils.Encrypt(msg, pubX, pubY, ks[1])
	inputs := map[string]any{
		"encryption_pubkey": []string{pubX.String(), pubY.String()},
		"k":                 k.String(),
		"msg":               msg.String(),
		"c1":                []string{c1[0].String(), c1[1].String()},
		"c2":                []string{c2[0].String(), c2[1].String()},
	}
	bInputs, _ := json.MarshalIndent(inputs, "  ", "  ")

	proofData, pubSignals, err := testutils.CompileAndGenerateProof(bInputs, wasmPath, zkeyPath)
	if err != nil {
		return
	}

	err = testutils.VerifyProof(proofData, pubSignals, vkey)
	c.Assert(err, qt.Not(qt.IsNil), qt.Commentf("wrong-subgroup public key should be rejected"))
}
