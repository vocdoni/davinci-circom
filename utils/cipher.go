package utils

import (
	"math/big"

	"github.com/consensys/gnark-crypto/ecc/bls12-377/fr"
	"github.com/consensys/gnark-crypto/ecc/bls12-377/twistededwards"
)

type PublicKey struct {
	X, Y big.Int
}

func GenerateKeyPair() (*big.Int, *PublicKey) {
	curve := twistededwards.GetEdwardsCurve()
	var priv fr.Element
	if _, err := priv.SetRandom(); err != nil {
		panic(err)
	}
	
	var pub twistededwards.PointAffine
	pub.ScalarMultiplication(&curve.Base, priv.BigInt(new(big.Int)))
	
	resPub := &PublicKey{}
	pub.X.BigInt(&resPub.X)
	pub.Y.BigInt(&resPub.Y)
	
	return priv.BigInt(new(big.Int)), resPub
}

func Encrypt(message *big.Int, pubKey *PublicKey, k *big.Int) ([2]big.Int, [2]big.Int) {
	curve := twistededwards.GetEdwardsCurve()
	
	var pubPoint twistededwards.PointAffine
	pubPoint.X.SetBigInt(&pubKey.X)
	pubPoint.Y.SetBigInt(&pubKey.Y)
	
	// c1 = [k] * G
	var c1 twistededwards.PointAffine
	c1.ScalarMultiplication(&curve.Base, k)
	
	// s = [k] * publicKey
	var s twistededwards.PointAffine
	s.ScalarMultiplication(&pubPoint, k)
	
	// m = [message] * G
	var m twistededwards.PointAffine
	m.ScalarMultiplication(&curve.Base, message)
	
	// c2 = m + s
	var c2 twistededwards.PointAffine
	c2.Add(&m, &s)
	
	var resC1, resC2 [2]big.Int
	c1.X.BigInt(&resC1[0])
	c1.Y.BigInt(&resC1[1])
	c2.X.BigInt(&resC2[0])
	c2.Y.BigInt(&resC2[1])
	
	return resC1, resC2
}
