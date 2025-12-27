package utils

import (
	"crypto/rand"
	"fmt"
	"math/big"

	"github.com/consensys/gnark-crypto/ecc/bls12-377/fr"
	"github.com/consensys/gnark-crypto/ecc/bls12-377/fr/mimc"
	"github.com/consensys/gnark-crypto/ecc/bls12-377/twistededwards"
)

func BigIntArrayToN(arr []*big.Int, n int) []*big.Int {
	bigArr := make([]*big.Int, n)
	for i := 0; i < n; i++ {
		if i < len(arr) {
			bigArr[i] = arr[i]
		} else {
			bigArr[i] = big.NewInt(0)
		}
	}
	return bigArr
}

func BigIntArrayToStringArray(arr []*big.Int, n int) []string {
	strArr := []string{}
	for _, b := range BigIntArrayToN(arr, n) {
		strArr = append(strArr, b.String())
	}
	return strArr
}

func RandomK() (*big.Int, error) {
	curve := twistededwards.GetEdwardsCurve()
	// Generate random scalar k mod curve.Order
	k, err := rand.Int(rand.Reader, &curve.Order)
	if err != nil {
		return nil, fmt.Errorf("failed to generate random k: %v", err)
	}
	return k, nil
}

func MiMCHash(inputs ...*big.Int) (*big.Int, error) {
	h := mimc.NewFieldHasher()
	for _, input := range inputs {
		var e fr.Element
		e.SetBigInt(input)
		h.WriteElement(e)
	}
	res := h.SumElement()
	return res.BigInt(new(big.Int)), nil
}

func VoteID(bigPID, bigAddr, k *big.Int) (*big.Int, error) {
	hash, err := MiMCHash(bigPID, bigAddr, k)
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
