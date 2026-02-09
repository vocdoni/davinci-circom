package testutils

import (
	"fmt"
	"math/big"

	"github.com/consensys/gnark-crypto/ecc/bn254/fr"
)

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
