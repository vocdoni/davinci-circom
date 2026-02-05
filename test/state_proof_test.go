package test

import (
	"encoding/json"
	"fmt"
	"math/big"
	"os"
	"testing"

	qt "github.com/frankban/quicktest"
	"github.com/vocdoni/davinci-circom/test/testutils"
)

type stateProofExample struct {
	name           string
	processIDHex   string
	censusOrigin   int64
	numFields      int64
	uniqueValues   int64
	maxValue       int64
	minValue       int64
	maxValueSum    int64
	minValueSum    int64
	costExponent   int64
	costFromWeight int64
	pubKeyX        string
	pubKeyY        string
	stateRootHex   string
}

func parseHex(hex string) (*big.Int, error) {
	clean := hex
	if len(clean) >= 2 && clean[:2] == "0x" {
		clean = clean[2:]
	}
	value, ok := new(big.Int).SetString(clean, 16)
	if !ok {
		return nil, fmt.Errorf("invalid hex: %s", hex)
	}
	return value, nil
}

func TestStateProof(t *testing.T) {
	c := qt.New(t)

	err := testutils.EnsureArtifacts(
		testutils.StateProofWasm,
		testutils.StateProofZkey,
		testutils.StateProofVkey,
	)
	c.Assert(err, qt.IsNil, qt.Commentf("artifacts check failed"))

	wasmPath, err := testutils.GetArtifactPath(testutils.StateProofWasm)
	c.Assert(err, qt.IsNil)
	zkeyPath, err := testutils.GetArtifactPath(testutils.StateProofZkey)
	c.Assert(err, qt.IsNil)
	vkeyPath, err := testutils.GetArtifactPath(testutils.StateProofVkey)
	c.Assert(err, qt.IsNil)

	examples := []stateProofExample{
		{
			name:           "example 1",
			processIDHex:   "0xa62e32147e9c1ea76da552be6e0636f1984143afafadd02a0000000000000054",
			censusOrigin:   1,
			numFields:      2,
			uniqueValues:   0,
			maxValue:       3,
			minValue:       0,
			maxValueSum:    6,
			minValueSum:    0,
			costExponent:   1,
			costFromWeight: 0,
			pubKeyX:        "16933062402632635736496659348042530570269601638203711496225900074829366889921",
			pubKeyY:        "11508164083883461513547825430852413119776037873858767460423492545044648001105",
			stateRootHex:   "0x2bfe7c9d72c0ba31fb9b98380a853988512cfd370cbdd0e612a2200021e3d2a8",
		},
		{
			name:           "example 2",
			processIDHex:   "0xa62e32147e9c1ea76da552be6e0636f1984143afafadd02a0000000000000052",
			censusOrigin:   1,
			numFields:      8,
			uniqueValues:   0,
			maxValue:       3,
			minValue:       0,
			maxValueSum:    6,
			minValueSum:    0,
			costExponent:   1,
			costFromWeight: 0,
			pubKeyX:        "1492682040326512594284755973658780253462029564060776960680900314510687633597",
			pubKeyY:        "7637432446709144246823592048956657247103456391796340456316224306151082192247",
			stateRootHex:   "0x24ca8ee12a764bb75106acbd42c57807804694ef5347d15b51a77a6b51ea8d28",
		},
	}

	for _, tc := range examples {
		t.Run(tc.name, func(t *testing.T) {
			c := qt.New(t)

			processID, err := parseHex(tc.processIDHex)
			c.Assert(err, qt.IsNil)
			stateRoot, err := parseHex(tc.stateRootHex)
			c.Assert(err, qt.IsNil)

			inputs := map[string]any{
				"state_root":        stateRoot.String(),
				"process_id":        processID.String(),
				"census_origin":     fmt.Sprintf("%d", tc.censusOrigin),
				"num_fields":        fmt.Sprintf("%d", tc.numFields),
				"unique_values":     fmt.Sprintf("%d", tc.uniqueValues),
				"max_value":         fmt.Sprintf("%d", tc.maxValue),
				"min_value":         fmt.Sprintf("%d", tc.minValue),
				"max_value_sum":     fmt.Sprintf("%d", tc.maxValueSum),
				"min_value_sum":     fmt.Sprintf("%d", tc.minValueSum),
				"cost_exponent":     fmt.Sprintf("%d", tc.costExponent),
				"cost_from_weight":  fmt.Sprintf("%d", tc.costFromWeight),
				"encryption_pubkey": []string{tc.pubKeyX, tc.pubKeyY},
			}
			inputBytes, err := json.MarshalIndent(inputs, "", "  ")
			c.Assert(err, qt.IsNil)

			proof, publicSignals, err := testutils.CompileAndGenerateProof(
				inputBytes,
				wasmPath,
				zkeyPath,
			)
			c.Assert(err, qt.IsNil)

			vkey, err := os.ReadFile(vkeyPath)
			c.Assert(err, qt.IsNil)

			err = testutils.VerifyProof(proof, publicSignals, vkey)
			c.Assert(err, qt.IsNil)
		})
	}
}
