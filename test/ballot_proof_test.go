package test

import (
	"crypto/rand"
	"encoding/json"
	"fmt"
	"math/big"
	"testing"
	"os"

	"github.com/consensys/gnark-crypto/ecc/bls12-377/fr"
	"github.com/vocdoni/poseidon377"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/vocdoni/z-ircuits/utils"
)

func randomBytes(n int) []byte {
	b := make([]byte, n)
	_, _ = rand.Read(b)
	return b
}

func toFr(i interface{}) fr.Element {
    var e fr.Element
    switch v := i.(type) {
    case int:
        e.SetUint64(uint64(v))
    case *big.Int:
        e.SetBigInt(v)
    case fr.Element:
        return v
    default:
        panic("unsupported type")
    }
    return e
}

func TestBallotProof(t *testing.T) {
	nFields := 8
	maxValue := 16
	maxValueSum := 1125
	minValue := 0
	minValueSum := 5
	uniqueValues := 1
	costExponent := 2
	costFromWeight := 0
	numFields := 5

	// Generate random inputs
	fields := make([]int, nFields)
	for i := 0; i < 5; i++ {
		fields[i] = i + 1
	}
	weight := 1

	_, pubkey := utils.GenerateKeyPair()
	k, err := utils.RandomK()
	require.NoError(t, err)

    // Derive k for each field recursively using Poseidon377
    // ks[0] = k
    // ks[i+1] = Hash(0, ks[i])
    ks := make([]*big.Int, nFields+1)
    ks[0] = k
    var domain fr.Element // 0
    
    for i := 0; i < nFields; i++ {
        h, err := poseidon377.Hash(domain, toFr(ks[i]))
        require.NoError(t, err)
        ks[i+1] = new(big.Int)
        h.BigInt(ks[i+1])
    }

	cipherfields := make([][2][2]*big.Int, nFields)
	for i := 0; i < nFields; i++ {
        // Circuit uses ks[i+1] for fields[i]
		c1, c2 := utils.Encrypt(big.NewInt(int64(fields[i])), pubkey, ks[i+1])
		c1x := new(big.Int).Set(&c1[0])
		c1y := new(big.Int).Set(&c1[1])
		c2x := new(big.Int).Set(&c2[0])
		c2y := new(big.Int).Set(&c2[1])
		
		cipherfields[i] = [2][2]*big.Int{
			{c1x, c1y},
			{c2x, c2y},
		}
	}

	processID := randomBytes(20)
	address := randomBytes(20)

	bigPID := new(big.Int).SetBytes(processID)
	bigAddr := new(big.Int).SetBytes(address)

	// Calculate VoteID using Poseidon377 (rate 3)
    // Hash(domain, pid, addr, k)
    voteIDRes, err := poseidon377.Hash(domain, toFr(bigPID), toFr(bigAddr), toFr(k))
    require.NoError(t, err)
	
	hashBig := new(big.Int)
	voteIDRes.BigInt(hashBig)
	mask := new(big.Int).Lsh(big.NewInt(1), 160)
	mask.Sub(mask, big.NewInt(1))
	voteIDTrunc := new(big.Int).And(hashBig, mask)

	// Calculate inputs_hash using Poseidon377 MultiHash
    var inputsList []fr.Element
    for i := 0; i < nFields; i++ {
        inputsList = append(inputsList, toFr(fields[i]))
    }
    inputsList = append(inputsList, toFr(weight))
    inputsList = append(inputsList, toFr(&pubkey.X))
    inputsList = append(inputsList, toFr(&pubkey.Y))
    
    for i := 0; i < nFields; i++ {
        inputsList = append(inputsList, toFr(cipherfields[i][0][0]))
        inputsList = append(inputsList, toFr(cipherfields[i][0][1]))
        inputsList = append(inputsList, toFr(cipherfields[i][1][0]))
        inputsList = append(inputsList, toFr(cipherfields[i][1][1]))
    }
    inputsList = append(inputsList, toFr(bigPID))
    inputsList = append(inputsList, toFr(bigAddr))
    inputsList = append(inputsList, toFr(k))
    inputsList = append(inputsList, toFr(voteIDTrunc))
    
    // Validation params
    inputsList = append(inputsList, toFr(numFields))
    inputsList = append(inputsList, toFr(uniqueValues))
    inputsList = append(inputsList, toFr(maxValue))
    inputsList = append(inputsList, toFr(minValue))
    inputsList = append(inputsList, toFr(maxValueSum))
    inputsList = append(inputsList, toFr(minValueSum))
    inputsList = append(inputsList, toFr(costExponent))
    inputsList = append(inputsList, toFr(costFromWeight))
    
    inputsHash, err := poseidon377.MultiHash(domain, inputsList...)
    require.NoError(t, err)

	inputs := map[string]any{
		"fields":            fields,
		"weight":            weight,
		"encryption_pubkey": []string{pubkey.X.String(), pubkey.Y.String()},
		"cipherfields":      cipherfields,
		"process_id":        bigPID.String(),
		"address":           bigAddr.String(),
		"k":                 k.String(),
		"vote_id":           voteIDTrunc.String(),
		"inputs_hash":       inputsHash.String(),
		"num_fields":        numFields,
		"unique_values":     uniqueValues,
		"max_value":         maxValue,
		"min_value":         minValue,
		"max_value_sum":     maxValueSum,
		"min_value_sum":     minValueSum,
		"cost_exponent":     costExponent,
		"cost_from_weight":  costFromWeight,
	}

	inputBytes, err := json.MarshalIndent(inputs, "", "  ")
	require.NoError(t, err)
	if persist && testID != "" {
		_ = os.WriteFile(fmt.Sprintf("../artifacts/%s_input.json", testID), inputBytes, 0644)
	}

	// Generate proof
	proof, publicSignals, err := utils.CompileAndGenerateProof(
		inputBytes,
		"../artifacts/ballot_proof_test.wasm",
		"../artifacts/ballot_proof_test_pkey.zkey",
	)
	require.NoError(t, err)

	// Verify proof
	vkey, err := os.ReadFile("../artifacts/ballot_proof_test_vkey.json")
	require.NoError(t, err)

	err = utils.VerifyProof(proof, publicSignals, vkey)
	assert.NoError(t, err)
}