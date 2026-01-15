package testutils

import (
	"fmt"
	"math/big"

	"github.com/consensys/gnark-crypto/ecc/bn254/fr"
	"github.com/iden3/go-iden3-crypto/poseidon"
)

// RandomK returns randomness in the BN254 scalar field.
func RandomK() (*big.Int, error) {
	var k fr.Element
	k.SetRandom()
	return k.BigInt(new(big.Int)), nil
}

// ToFr converts supported numeric types to an fr.Element.
func ToFr(i interface{}) fr.Element {
	var e fr.Element
	switch v := i.(type) {
	case int:
		e.SetUint64(uint64(v))
	case *big.Int:
		e.SetBigInt(v)
	case fr.Element:
		return v
	default:
		panic(fmt.Sprintf("unsupported type for ToFr: %T", i))
	}
	return e
}

// PoseidonHash computes the Poseidon hash of inputs (using iden3 implementation).
func PoseidonHash(inputs ...*big.Int) (*big.Int, error) {
	return poseidon.Hash(inputs)
}

// MultiHash matches circuits/lib/multiposeidon.circom logic.
// Max 256 inputs.
func MultiHash(inputs []*big.Int) (*big.Int, error) {
	nInputs := len(inputs)
	if nInputs <= 16 {
		return PoseidonHash(inputs...)
	}
	
	var intermediateHashes []*big.Int
	for i := 0; i < nInputs; i += 16 {
		end := i + 16
		if end > nInputs {
			end = nInputs
		}
		chunk := inputs[i:end]
		h, err := PoseidonHash(chunk...)
		if err != nil {
			return nil, err
		}
		intermediateHashes = append(intermediateHashes, h)
	}
	
	return PoseidonHash(intermediateHashes...)
}

func VoteID(bigPID, bigAddr, k *big.Int) (*big.Int, error) {
	hash, err := PoseidonHash(bigPID, bigAddr, k)
	if err != nil {
		return nil, fmt.Errorf("failed to generate vote ID: %v", err)
	}
	return TruncateTo160Bits(hash), nil
}

func TruncateTo160Bits(input *big.Int) *big.Int {
	mask := new(big.Int).Lsh(big.NewInt(1), 160) // 1 << 160
	mask.Sub(mask, big.NewInt(1))                // (1 << 160) - 1
	return new(big.Int).And(input, mask)         // input & ((1<<160)-1)
}

// DerivePoseidonChain derives n+1 values where out[0]=seed and out[i+1]=Hash(out[i]).
func DerivePoseidonChain(seed *big.Int, n int) ([]*big.Int, error) {
	out := make([]*big.Int, n+1)
	out[0] = new(big.Int).Set(seed)
	for i := 0; i < n; i++ {
		h, err := PoseidonHash(out[i])
		if err != nil {
			return nil, err
		}
		out[i+1] = h
	}
	return out, nil
}
