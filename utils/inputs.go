package utils

import (
	"crypto/rand"
	"math/big"
)

func GenerateBallotFields(n, max, min int, unique bool) []*big.Int {
	fields := []*big.Int{}
	stored := map[string]bool{}
	for i := 0; i < n; i++ {
		for {
			// generate random field
			field, err := rand.Int(rand.Reader, big.NewInt(int64(max-min)))
			if err != nil {
				panic(err)
			}
			field.Add(field, big.NewInt(int64(min)))
			// if it should be unique and it's already stored, skip it,
			// otherwise add it to the list of fields and continue
			if !unique || !stored[field.String()] {
				fields = append(fields, field)
				stored[field.String()] = true
				break
			}
		}
	}
	return fields
}

func CipherBallotFields(fields []*big.Int, n int, pk *PublicKey, k *big.Int) ([][][]string, []*big.Int) {
	cipherfields := make([][][]string, n)
	plainCipherfields := []*big.Int{}

	lastK, err := MiMCHash(k)
	if err != nil {
		panic(err)
	}
	for i := 0; i < n; i++ {
		if i < len(fields) {
			c1, c2 := Encrypt(fields[i], pk, lastK)
			cipherfields[i] = [][]string{
				{c1[0].String(), c1[1].String()},
				{c2[0].String(), c2[1].String()},
			}
			plainCipherfields = append(plainCipherfields, &c1[0], &c1[1], &c2[0], &c2[1])
		} else {
			cipherfields[i] = [][]string{
				{"0", "0"},
				{"0", "0"},
			}
			zero := big.NewInt(0)
			plainCipherfields = append(plainCipherfields, zero, zero, zero, zero)
		}
		var err error
		lastK, err = MiMCHash(lastK)
		if err != nil {
			panic(err)
		}
	}
	return cipherfields, plainCipherfields
}

func MockedCommitmentAndNullifier(address, processID, secret []byte) (*big.Int, *big.Int, error) {
	commitment, err := MiMCHash(
		new(big.Int).SetBytes(address),
		new(big.Int).SetBytes(processID),
		new(big.Int).SetBytes(secret),
	)
	if err != nil {
		return nil, nil, err
	}
	nullifier, err := MiMCHash(
		commitment,
		new(big.Int).SetBytes(secret),
	)
	if err != nil {
		return nil, nil, err
	}
	return commitment, nullifier, nil
}