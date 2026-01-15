package testutils

import (
	"math/big"

	"github.com/consensys/gnark-crypto/ecc/bn254/fr"
	"github.com/consensys/gnark-crypto/ecc/bn254/twistededwards"
)

// scalingFactor used to transform between BabyJubJub forms.
// See davinci-node/crypto/ecc/format/twistededwards.go
var scalingFactor, _ = new(big.Int).SetString("6360561867910373094066688120553762416144456282423235903351243436111059670888", 10)

// FromRTEtoTE converts a point from Reduced TwistedEdwards (Gnark) to TwistedEdwards (Circom/Iden3) coordinates.
// It applies the transformation:
//
//      x = x'/(-f)
//      y = y'
func FromRTEtoTE(x, y *big.Int) (*big.Int, *big.Int) {
	var f fr.Element
	f.SetBigInt(scalingFactor)

	var negF fr.Element
	negF.Neg(&f)

	var negFInv fr.Element
	negFInv.Inverse(&negF)

	xRTE := new(fr.Element).SetBigInt(x)
	xTE := new(fr.Element)
	xTE.Mul(xRTE, &negFInv)

	xTEBigInt := new(big.Int)
	xTE.BigInt(xTEBigInt)
	return xTEBigInt, y
}

// GenerateKeyPair returns a private/public key pair using Gnark's library,
// but converts the public key to Circom-compatible coordinates (Standard Twisted Edwards).
func GenerateKeyPair() (*big.Int, *big.Int, *big.Int) {
	// Generate key on Gnark's BabyJubJub (Reduced Twisted Edwards, a=-1)
	curve := twistededwards.GetEdwardsCurve()
	
	// Create private key in subgroup
	priv, err := randK()
	if err != nil {
		panic(err)
	}
	priv.Mod(priv, &curve.Order)

	// Calculate public key on Gnark's curve
	var pub twistededwards.PointAffine
	pub.ScalarMultiplication(&curve.Base, priv)

	xRTE := pub.X.BigInt(new(big.Int))
	yRTE := pub.Y.BigInt(new(big.Int))

	// Convert to Circom coordinates
	xTE, yTE := FromRTEtoTE(xRTE, yRTE)
	return priv, xTE, yTE
}

func randK() (*big.Int, error) {
	var k fr.Element
	k.SetRandom()
	return k.BigInt(new(big.Int)), nil
}

// Encrypt encrypts message with the provided public key (in Circom form) and randomness k.
// Returns ciphertext points (C1, C2) in Circom form.
// Logic:
// 1. Convert PubKey(TE) -> PubKey(RTE)
// 2. Perform scalar mul/add on Gnark curve (RTE)
// 3. Convert Result(RTE) -> Result(TE)
func Encrypt(message *big.Int, pubKeyX, pubKeyY *big.Int, k *big.Int) ([2]big.Int, [2]big.Int) {
	curve := twistededwards.GetEdwardsCurve()

	// Convert PubKey back to RTE for computation
	pubX_RTE, pubY_RTE := FromTEtoRTE(pubKeyX, pubKeyY)
	pubRTE := twistededwards.PointAffine{
		X: *new(fr.Element).SetBigInt(pubX_RTE),
		Y: *new(fr.Element).SetBigInt(pubY_RTE),
	}

	// C1 = k * Base (Base is already in RTE in Gnark)
	var c1 twistededwards.PointAffine
	c1.ScalarMultiplication(&curve.Base, k)

	// S = k * Pub
	var s twistededwards.PointAffine
	s.ScalarMultiplication(&pubRTE, k)

	// MPoint = M * Base
	var mPoint twistededwards.PointAffine
	mPoint.ScalarMultiplication(&curve.Base, message)

	// C2 = MPoint + S
	var c2 twistededwards.PointAffine
	c2.Add(&mPoint, &s)

	// Convert results to Circom form (TE)
	x1_TE, y1_TE := FromRTEtoTE(c1.X.BigInt(new(big.Int)), c1.Y.BigInt(new(big.Int)))
	x2_TE, y2_TE := FromRTEtoTE(c2.X.BigInt(new(big.Int)), c2.Y.BigInt(new(big.Int)))

	var resC1, resC2 [2]big.Int
	resC1[0].Set(x1_TE)
	resC1[1].Set(y1_TE)
	resC2[0].Set(x2_TE)
	resC2[1].Set(y2_TE)

	return resC1, resC2
}

// FromTEtoRTE helper
func FromTEtoRTE(x, y *big.Int) (*big.Int, *big.Int) {
	var f fr.Element
	f.SetBigInt(scalingFactor)
	var negF fr.Element
	negF.Neg(&f)

	xTE := new(fr.Element).SetBigInt(x)
	xRTE := new(fr.Element)
	xRTE.Mul(xTE, &negF)

	xRTEBigInt := new(big.Int)
	xRTE.BigInt(xRTEBigInt)
	return xRTEBigInt, y
}