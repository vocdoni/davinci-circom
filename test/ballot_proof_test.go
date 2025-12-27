package test

import (
	"crypto/rand"
	"encoding/json"
	"fmt"
	"math/big"
	"testing"
	"os"

	"github.com/consensys/gnark-crypto/ecc/bls12-377/fr"
	"github.com/consensys/gnark-crypto/ecc/bls12-377/fr/poseidon2"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/vocdoni/z-ircuits/utils"
)

func randomBytes(n int) []byte {
	b := make([]byte, n)
	rand.Read(b)
	return b
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

	cipherfields := make([][2][2]*big.Int, nFields)
	for i := 0; i < nFields; i++ {
		c1, c2 := utils.Encrypt(big.NewInt(int64(fields[i])), pubkey, k)
		// c1 is [2]big.Int
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

	// Calculate VoteID using Poseidon2
	h := poseidon2.NewMerkleDamgardHasher()
	var e fr.Element
	e.SetBigInt(bigPID)
	b := e.Bytes()
	h.Write(b[:])
	e.SetBigInt(bigAddr)
	b = e.Bytes()
	h.Write(b[:])
	e.SetBigInt(k)
	b = e.Bytes()
	h.Write(b[:])
	
	res := h.Sum(nil)
	var voteID fr.Element
	voteID.SetBytes(res)
	
	hashBig := new(big.Int)
	voteID.BigInt(hashBig)
	mask := new(big.Int).Lsh(big.NewInt(1), 160)
	mask.Sub(mask, big.NewInt(1))
	voteIDTrunc := new(big.Int).And(hashBig, mask)

	// Calculate inputs_hash using Poseidon2
	h2 := poseidon2.NewMerkleDamgardHasher()
	for i := 0; i < nFields; i++ {
		e.SetUint64(uint64(fields[i]))
		b = e.Bytes()
		h2.Write(b[:])
	}
	e.SetUint64(uint64(weight))
	b = e.Bytes()
	h2.Write(b[:])
	
	e.SetBigInt(&pubkey.X)
	b = e.Bytes()
	h2.Write(b[:])
	e.SetBigInt(&pubkey.Y)
	b = e.Bytes()
	h2.Write(b[:])
	
	for i := 0; i < nFields; i++ {
		e.SetBigInt(cipherfields[i][0][0])
		b = e.Bytes()
		h2.Write(b[:])
		e.SetBigInt(cipherfields[i][0][1])
		b = e.Bytes()
		h2.Write(b[:])
		e.SetBigInt(cipherfields[i][1][0])
		b = e.Bytes()
		h2.Write(b[:])
		e.SetBigInt(cipherfields[i][1][1])
		b = e.Bytes()
		h2.Write(b[:])
	}
	
	e.SetBigInt(bigPID)
	b = e.Bytes()
	h2.Write(b[:])
	e.SetBigInt(bigAddr)
	b = e.Bytes()
	h2.Write(b[:])
	e.SetBigInt(k)
	b = e.Bytes()
	h2.Write(b[:])
	e.SetBigInt(voteIDTrunc)
	b = e.Bytes()
	h2.Write(b[:])
	
	// Validation params
	e.SetUint64(uint64(numFields))
	b = e.Bytes()
	h2.Write(b[:])
	e.SetUint64(uint64(uniqueValues))
	b = e.Bytes()
	h2.Write(b[:])
	e.SetUint64(uint64(maxValue))
	b = e.Bytes()
	h2.Write(b[:])
	e.SetUint64(uint64(minValue))
	b = e.Bytes()
	h2.Write(b[:])
	e.SetUint64(uint64(maxValueSum))
	b = e.Bytes()
	h2.Write(b[:])
	e.SetUint64(uint64(minValueSum))
	b = e.Bytes()
	h2.Write(b[:])
	e.SetUint64(uint64(costExponent))
	b = e.Bytes()
	h2.Write(b[:])
	e.SetUint64(uint64(costFromWeight))
	b = e.Bytes()
	h2.Write(b[:])

	inputsHashRes := h2.Sum(nil)
	var inputsHash fr.Element
	inputsHash.SetBytes(inputsHashRes)

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
		_ = os.WriteFile(fmt.Sprintf("artifacts/%s_input.json", testID), inputBytes, 0644)
	}

	// Generate proof
	proof, publicSignals, err := utils.CompileAndGenerateProof(
		inputBytes,
		"artifacts/ballot_proof_test.wasm",
		"artifacts/ballot_proof_test_pkey.zkey",
	)
	require.NoError(t, err)

	// Verify proof
	vkey, err := os.ReadFile("artifacts/ballot_proof_test_vkey.json")
	require.NoError(t, err)

	err = utils.VerifyProof(proof, publicSignals, vkey)
	assert.NoError(t, err)
}