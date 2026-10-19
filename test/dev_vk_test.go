package test

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"math/big"
	"os"
	"strings"
	"testing"

	qt "github.com/frankban/quicktest"
	"github.com/vocdoni/davinci-circom/test/testutils"
)

type snarkjsVK struct {
	Setup   string       `json:"setup"`
	NPublic int          `json:"nPublic"`
	Alpha   [3]string    `json:"vk_alpha_1"`
	Beta    [3][2]string `json:"vk_beta_2"`
	Gamma   [3][2]string `json:"vk_gamma_2"`
	Delta   [3][2]string `json:"vk_delta_2"`
	IC      [][3]string  `json:"IC"`
}

// vkWireHash is sha256 of the VK wire bytes the zkVM guest hashes into config
// leaf 0x07 (davinci-zkvm rust-sdk groth16.rs): alpha_1, beta_2, gamma_2,
// delta_2, u64 LE IC count, IC; each coordinate 32 bytes little-endian, an
// identity point all zeros.
func vkWireHash(t *testing.T, vk *snarkjsVK) string {
	var buf []byte
	put := func(dec string) {
		v, ok := new(big.Int).SetString(dec, 10)
		if !ok || v.Sign() < 0 || v.BitLen() > 256 {
			t.Fatalf("bad coordinate %q", dec)
		}
		var b [32]byte
		v.FillBytes(b[:])
		for i, j := 0, 31; i < j; i, j = i+1, j-1 {
			b[i], b[j] = b[j], b[i]
		}
		buf = append(buf, b[:]...)
	}
	g1 := func(p [3]string) {
		if p[2] == "0" {
			buf = append(buf, make([]byte, 64)...)
			return
		}
		put(p[0])
		put(p[1])
	}
	g2 := func(p [3][2]string) {
		if p[2][0] == "0" && p[2][1] == "0" {
			buf = append(buf, make([]byte, 128)...)
			return
		}
		put(p[0][0])
		put(p[0][1])
		put(p[1][0])
		put(p[1][1])
	}
	g1(vk.Alpha)
	g2(vk.Beta)
	g2(vk.Gamma)
	g2(vk.Delta)
	buf = binary.LittleEndian.AppendUint64(buf, uint64(len(vk.IC)))
	for _, p := range vk.IC {
		g1(p)
	}
	d := sha256.Sum256(buf)
	return hex.EncodeToString(d[:])
}

// TestDevVKHash fails CI when `make prepare` no longer reproduces the pinned
// dev key: the hash is pinned in davinci-zkvm, the registry deploy and the TS
// SDK, so a change must be deliberate.
func TestDevVKHash(t *testing.T) {
	c := qt.New(t)
	vkPath, err := testutils.GetArtifactPath(testutils.BallotProofVkey)
	c.Assert(err, qt.IsNil)
	raw, err := os.ReadFile(vkPath)
	c.Assert(err, qt.IsNil)
	var vk snarkjsVK
	c.Assert(json.Unmarshal(raw, &vk), qt.IsNil)

	c.Assert(vk.Setup, qt.Equals, "dev")
	c.Assert(vk.NPublic, qt.Equals, 71)
	c.Assert(vk.IC, qt.HasLen, 72)
	c.Assert(vk.Delta, qt.Not(qt.DeepEquals), vk.Gamma, qt.Commentf("VK without a phase-2 contribution"))

	pinPath, err := testutils.GetArtifactPath("DEV_VK_HASH")
	c.Assert(err, qt.IsNil)
	pin, err := os.ReadFile(pinPath)
	c.Assert(err, qt.IsNil)
	got := vkWireHash(t, &vk)
	c.Assert(got, qt.Equals, strings.TrimSpace(string(pin)),
		qt.Commentf("if the circuit or setup changed on purpose, write %s to artifacts/DEV_VK_HASH", got))
}
