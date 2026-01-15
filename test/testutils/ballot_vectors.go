package testutils

import (
	"crypto/rand"
	"encoding/json"
	"math/big"
)

// BallotVectors holds a reproducible set of inputs for the ballot circuits.
type BallotVectors struct {
	Fields         []int
	Weight         int
	PubKeyX        *big.Int
	PubKeyY        *big.Int
	Cipherfields   [][2][2]*big.Int
	ProcessID      *big.Int
	Address        *big.Int
	K              *big.Int
	VoteID         *big.Int
	InputsHash     *big.Int
	NumFields      int
	UniqueValues   int
	MaxValue       int
	MinValue       int
	MaxValueSum    int
	MinValueSum    int
	CostExponent   int
	CostFromWeight int
}

func randomBytes(n int) []byte {
	b := make([]byte, n)
	_, _ = rand.Read(b)
	return b
}

// BuildBallotVectors creates fresh valid inputs matching the circom ballot circuits.
func BuildBallotVectors() (*BallotVectors, error) {
	nFields := 8
	maxValue := 16
	maxValueSum := 1125
	minValue := 0
	minValueSum := 5
	uniqueValues := 1
	costExponent := 2
	costFromWeight := 0
	numFields := 5

	fields := make([]int, nFields)
	for i := 0; i < numFields; i++ {
		fields[i] = i + 1
	}
	weight := 1

	// Updated to use the new GenerateKeyPair that returns (priv, x, y)
	_, pubX, pubY := GenerateKeyPair()

	k, err := RandomK()
	if err != nil {
		return nil, err
	}

	ks, err := DerivePoseidonChain(k, nFields)
	if err != nil {
		return nil, err
	}

	cipherfields := make([][2][2]*big.Int, nFields)
	for i := 0; i < nFields; i++ {
		// Updated Encrypt call signature: Encrypt(msg, pubX, pubY, k)
		c1, c2 := Encrypt(big.NewInt(int64(fields[i])), pubX, pubY, ks[i+1])
		cipherfields[i] = [2][2]*big.Int{
			{new(big.Int).Set(&c1[0]), new(big.Int).Set(&c1[1])},
			{new(big.Int).Set(&c2[0]), new(big.Int).Set(&c2[1])},
		}
	}

	processID := new(big.Int).SetBytes(randomBytes(20))
	address := new(big.Int).SetBytes(randomBytes(20))

	// voteID uses priv K directly
	voteID, err := VoteID(processID, address, k)
	if err != nil {
		return nil, err
	}

	var inputsList []*big.Int
	inputsList = append(inputsList, processID)
	inputsList = append(inputsList, big.NewInt(int64(numFields)))
	inputsList = append(inputsList, big.NewInt(int64(uniqueValues)))
	inputsList = append(inputsList, big.NewInt(int64(maxValue)))
	inputsList = append(inputsList, big.NewInt(int64(minValue)))
	inputsList = append(inputsList, big.NewInt(int64(maxValueSum)))
	inputsList = append(inputsList, big.NewInt(int64(minValueSum)))
	inputsList = append(inputsList, big.NewInt(int64(costExponent)))
	inputsList = append(inputsList, big.NewInt(int64(costFromWeight)))
	
	inputsList = append(inputsList, pubX)
	inputsList = append(inputsList, pubY)
	
	inputsList = append(inputsList, address)
	inputsList = append(inputsList, voteID)
	
	for i := 0; i < nFields; i++ {
		inputsList = append(inputsList, cipherfields[i][0][0])
		inputsList = append(inputsList, cipherfields[i][0][1])
		inputsList = append(inputsList, cipherfields[i][1][0])
		inputsList = append(inputsList, cipherfields[i][1][1])
	}
	inputsList = append(inputsList, big.NewInt(int64(weight)))

	inputsHash, err := MultiHash(inputsList)
	if err != nil {
		return nil, err
	}

	return &BallotVectors{
		Fields:         fields,
		Weight:         weight,
		PubKeyX:        pubX,
		PubKeyY:        pubY,
		Cipherfields:   cipherfields,
		ProcessID:      processID,
		Address:        address,
		K:              k,
		VoteID:         voteID,
		InputsHash:     inputsHash,
		NumFields:      numFields,
		UniqueValues:   uniqueValues,
		MaxValue:       maxValue,
		MinValue:       minValue,
		MaxValueSum:    maxValueSum,
		MinValueSum:    minValueSum,
		CostExponent:   costExponent,
		CostFromWeight: costFromWeight,
	}, nil
}

// InputsMap returns the JSON-friendly map expected by snarkjs/ballot circuits.
func (b *BallotVectors) InputsMap() map[string]any {
	return map[string]any{
		"fields":            b.Fields,
		"weight":            b.Weight,
		"encryption_pubkey": []string{b.PubKeyX.String(), b.PubKeyY.String()},
		"cipherfields":      StringifyCipherfields(b.Cipherfields),
		"process_id":        b.ProcessID.String(),
		"address":           b.Address.String(),
		"k":                 b.K.String(),
		"vote_id":           b.VoteID.String(),
		"inputs_hash":       b.InputsHash.String(),
		"num_fields":        b.NumFields,
		"unique_values":     b.UniqueValues,
		"max_value":         b.MaxValue,
		"min_value":         b.MinValue,
		"max_value_sum":     b.MaxValueSum,
		"min_value_sum":     b.MinValueSum,
		"cost_exponent":     b.CostExponent,
		"cost_from_weight":  b.CostFromWeight,
	}
}

// MarshalInputs returns the circom input JSON bytes.
func (b *BallotVectors) MarshalInputs() ([]byte, error) {
	return json.Marshal(b.InputsMap())
}

// StringifyCipherfields converts big.Int cipherfields to strings for circom input.
func StringifyCipherfields(cf [][2][2]*big.Int) [][2][2]string {
	out := make([][2][2]string, len(cf))
	for i := range cf {
		for j := 0; j < 2; j++ {
			for k := 0; k < 2; k++ {
				out[i][j][k] = cf[i][j][k].String()
			}
		}
	}
	return out
}