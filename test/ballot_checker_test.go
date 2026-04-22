package test

import (
	"encoding/json"
	"os"
	"strconv"
	"testing"

	qt "github.com/frankban/quicktest"
	"github.com/vocdoni/davinci-circom/test/testutils"
)

// padToEight returns a slice of length 8, copying the caller-supplied values
// and zero-filling the remainder (or truncating if more than 8).
func padToEight(vals []int64) []int64 {
	out := make([]int64, 8)
	copy(out, vals)
	return out
}

// ballotToStrings converts an int64 slice to the string slice expected by the
// circom circuit.
func ballotToStrings(vals []int64) []string {
	out := make([]string, len(vals))
	for i, v := range vals {
		out[i] = strconv.FormatInt(v, 10)
	}
	return out
}

func TestBallotChecker(t *testing.T) {
	c := qt.New(t)
	type tc struct {
		name           string
		fields         []int64 // raw field values (<= 8 non-zero entries)
		numFields      int     // logical field count provided by the ballot
		forceUnique    bool    // uniqueness flag
		maxValue       int
		minValue       int
		maxValueSum    int
		minValueSum    int
		costExp        int
		expectPass     bool
		costFromWeight bool
		weight         int
	}

	cases := []tc{
		{
			name:        "Simple 5-star rating - valid",
			fields:      []int64{3, 2, 5},
			numFields:   3,
			forceUnique: true,
			maxValue:    5,
			minValue:    0,
			maxValueSum: 15,
			minValueSum: 0,
			costExp:     1,
			expectPass:  true,
		},
		{
			name:        "Duplicate values with uniqueness required - invalid",
			fields:      []int64{3, 3, 1},
			numFields:   3,
			forceUnique: true,
			maxValue:    5,
			minValue:    0,
			maxValueSum: 16,
			minValueSum: 0,
			costExp:     1,
			expectPass:  false,
		},
		{
			name:        "Maxvalue is correctly verified and maxValueSum=0 is ignored - valid",
			fields:      []int64{50, 49, 48},
			numFields:   3,
			forceUnique: false,
			maxValue:    50,
			minValue:    0,
			maxValueSum: 0,
			minValueSum: 0,
			costExp:     1,
			expectPass:  true,
		},
		{
			name:        "Value exceeds maxValue - invalid",
			fields:      []int64{13, 0, 0},
			numFields:   3,
			forceUnique: false,
			maxValue:    12,
			minValue:    0,
			maxValueSum: 15,
			minValueSum: 0,
			costExp:     1,
			expectPass:  false,
		},
		{
			name:        "Value underflows minValue - invalid",
			fields:      []int64{1, 0, 0},
			numFields:   3,
			forceUnique: false,
			maxValue:    11,
			minValue:    5,
			maxValueSum: 1000,
			minValueSum: 0,
			costExp:     1,
			expectPass:  false,
		},
		{
			name:        "Quadratic voting cost within limit - valid",
			fields:      []int64{2, 2, 2}, // cost = 4+4+4 = 12
			numFields:   3,
			forceUnique: false,
			maxValue:    4,
			minValue:    0,
			maxValueSum: 12,
			minValueSum: 0,
			costExp:     2,
			expectPass:  true,
		},
		{
			name:        "Quadratic voting cost exceeds limit - invalid",
			fields:      []int64{3, 2, 1}, // cost = 9+4+1 = 14 > 13
			numFields:   3,
			forceUnique: false,
			maxValue:    4,
			minValue:    0,
			maxValueSum: 13,
			minValueSum: 0,
			costExp:     2,
			expectPass:  false,
		},
		{
			name:        "minValueSum not reached - invalid",
			fields:      []int64{2, 0, 0}, // cost = 4 < 5
			numFields:   3,
			forceUnique: false,
			maxValue:    4,
			minValue:    0,
			maxValueSum: 20,
			minValueSum: 5,
			costExp:     2,
			expectPass:  false,
		},
		{
			name:        "Duplicates allowed when uniqueness off - valid",
			fields:      []int64{5, 5, 0},
			numFields:   3,
			forceUnique: false,
			maxValue:    5,
			minValue:    0,
			maxValueSum: 15,
			minValueSum: 0,
			costExp:     1,
			expectPass:  true,
		},
		{
			name:        "Approval voting - exactly 3 of 6 chosen - valid",
			fields:      []int64{1, 0, 1, 0, 1, 0},
			numFields:   6,
			forceUnique: false,
			maxValue:    1,
			minValue:    0,
			maxValueSum: 3,
			minValueSum: 3,
			costExp:     1,
			expectPass:  true,
		},
		{
			name:        "Approval voting - choose 4 out of 6 (exceeds limit) - invalid",
			fields:      []int64{1, 1, 1, 1, 0, 0}, // cost 4 > 3
			numFields:   6,
			forceUnique: false,
			maxValue:    1,
			minValue:    0,
			maxValueSum: 3,
			minValueSum: 3,
			costExp:     1,
			expectPass:  false,
		},
		{
			name:        "Ranked-choice voting - unique ranks 1..3 - valid",
			fields:      []int64{1, 2, 3}, // sum = 6
			numFields:   3,
			forceUnique: true,
			maxValue:    3,
			minValue:    1,
			maxValueSum: 6,
			minValueSum: 6,
			costExp:     1,
			expectPass:  true,
		},
		{
			name:        "Ranked-choice voting - duplicate rank - invalid",
			fields:      []int64{1, 1, 2},
			numFields:   3,
			forceUnique: true,
			maxValue:    3,
			minValue:    1,
			maxValueSum: 6,
			minValueSum: 6,
			costExp:     1,
			expectPass:  false,
		},
		{
			name:        "All zeros but minValueSum positive - invalid",
			fields:      []int64{0, 0, 0},
			numFields:   3,
			forceUnique: false,
			maxValue:    5,
			minValue:    0,
			maxValueSum: 10,
			minValueSum: 1,
			costExp:     1,
			expectPass:  false,
		},
		{
			name:           "Exceed asigned weight - invalid",
			fields:         []int64{25, 0, 0, 0},
			numFields:      4,
			forceUnique:    false,
			maxValue:       50,
			minValue:       0,
			maxValueSum:    0,
			minValueSum:    0,
			costExp:        1,
			expectPass:     false,
			costFromWeight: true,
			weight:         10,
		},
		{
			name:           "Less value than assigned weight - valid",
			fields:         []int64{25, 0, 0, 0},
			numFields:      4,
			forceUnique:    false,
			maxValue:       50,
			minValue:       0,
			maxValueSum:    0,
			minValueSum:    0,
			costExp:        1,
			expectPass:     true,
			costFromWeight: true,
			weight:         50,
		},
		{
			name:           "Exceed assigned weight but without max value sum - valid",
			fields:         []int64{75, 0, 0, 0},
			numFields:      4,
			forceUnique:    false,
			maxValue:       75,
			minValue:       0,
			maxValueSum:    0,
			minValueSum:    0,
			costExp:        1,
			expectPass:     true,
			costFromWeight: false,
			weight:         50,
		},
	}

	// Get artifact paths
	wasmPath, err := testutils.GetArtifactPath(testutils.BallotCheckerWasm)
	c.Assert(err, qt.IsNil)
	zkeyPath, err := testutils.GetArtifactPath(testutils.BallotCheckerZkey)
	c.Assert(err, qt.IsNil)
	vkeyPath, err := testutils.GetArtifactPath(testutils.BallotCheckerVkey)
	c.Assert(err, qt.IsNil)

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			c := qt.New(t)

			// Pad or truncate the ballot to exactly eight positions.
			padded := padToEight(tc.fields)

			// Force-uniqueness flag as string (circom expects 0/1, not bool).
			uniq := "0"
			if tc.forceUnique {
				uniq = "1"
			}
			costFromWeight := "0"
			if tc.costFromWeight {
				costFromWeight = "1"
			}

			inputs := map[string]any{
				"fields":           ballotToStrings(padded),
				"num_fields":       strconv.Itoa(tc.numFields),
				"group_size":       strconv.Itoa(tc.numFields),
				"unique_values":    uniq,
				"max_value":        strconv.Itoa(tc.maxValue),
				"min_value":        strconv.Itoa(tc.minValue),
				"max_value_sum":    strconv.Itoa(tc.maxValueSum),
				"min_value_sum":    strconv.Itoa(tc.minValueSum),
				"cost_exponent":    strconv.Itoa(tc.costExp),
				"weight":           strconv.Itoa(tc.weight),
				"cost_from_weight": costFromWeight,
			}

			bInputs, err := json.MarshalIndent(inputs, "  ", "  ")
			c.Assert(err, qt.IsNil)

			c.Logf("\n[%s] Inputs:\n%s\n", tc.name, string(bInputs))

			proofData, pubSignals, err := testutils.CompileAndGenerateProof(bInputs, wasmPath, zkeyPath)
			c.Assert(tc.expectPass, qt.Equals, err == nil)

			// Failure is acceptable at either stage for negative tests.
			if tc.expectPass || err == nil {
				vkey, err := os.ReadFile(vkeyPath)
				c.Assert(err, qt.IsNil)
				err = testutils.VerifyProof(proofData, pubSignals, vkey)
				c.Assert(tc.expectPass, qt.Equals, err == nil)
			}
		})
	}
}
