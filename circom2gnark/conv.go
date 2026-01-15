package circom2gnark

import (
	"fmt"

	bn254 "github.com/consensys/gnark-crypto/ecc/bn254"
	bn254fr "github.com/consensys/gnark-crypto/ecc/bn254/fr"
	groth16_bn254 "github.com/consensys/gnark/backend/groth16/bn254"
)

// ConvertPublicInputsBN254 parses public inputs into BN254 field elements.
func ConvertPublicInputsBN254(publicSignals []string) ([]bn254fr.Element, error) {
	publicInputs := make([]bn254fr.Element, len(publicSignals))
	for i, s := range publicSignals {
		bi, err := stringToBigInt(s)
		if err != nil {
			return nil, fmt.Errorf("failed to parse public input %d: %v", i, err)
		}
		publicInputs[i].SetBigInt(bi)
	}
	return publicInputs, nil
}

// ToGnarkBN254 converts a CircomProof into a Gnark-compatible Proof structure over BN254.
func (circomProof *CircomProof) ToGnarkBN254() (*groth16_bn254.Proof, error) {
	arG1, err := stringToG1BN254(circomProof.PiA)
	if err != nil {
		return nil, fmt.Errorf("failed to convert PiA: %v", err)
	}
	krsG1, err := stringToG1BN254(circomProof.PiC)
	if err != nil {
		return nil, fmt.Errorf("failed to convert PiC: %v", err)
	}
	bsG2, err := stringToG2BN254(circomProof.PiB)
	if err != nil {
		return nil, fmt.Errorf("failed to convert PiB: %v", err)
	}
	return &groth16_bn254.Proof{
		Ar:  *arG1,
		Krs: *krsG1,
		Bs:  *bsG2,
	}, nil
}

// ToGnarkBN254 converts a CircomVerificationKey into a Gnark-compatible verification key over BN254.
func (circomVerificationKey *CircomVerificationKey) ToGnarkBN254() (*groth16_bn254.VerifyingKey, error) {
	alphaG1, err := stringToG1BN254(circomVerificationKey.VkAlpha1)
	if err != nil {
		return nil, fmt.Errorf("failed to convert VkAlpha1: %v", err)
	}
	betaG2, err := stringToG2BN254(circomVerificationKey.VkBeta2)
	if err != nil {
		return nil, fmt.Errorf("failed to convert VkBeta2: %v", err)
	}
	gammaG2, err := stringToG2BN254(circomVerificationKey.VkGamma2)
	if err != nil {
		return nil, fmt.Errorf("failed to convert VkGamma2: %v", err)
	}
	deltaG2, err := stringToG2BN254(circomVerificationKey.VkDelta2)
	if err != nil {
		return nil, fmt.Errorf("failed to convert VkDelta2: %v", err)
	}

	numIC := len(circomVerificationKey.IC)
	G1K := make([]bn254.G1Affine, numIC)
	for i, icPoint := range circomVerificationKey.IC {
		icG1, err := stringToG1BN254(icPoint)
		if err != nil {
			return nil, fmt.Errorf("failed to convert IC[%d]: %v", i, err)
		}
		G1K[i] = *icG1
	}

	vk := &groth16_bn254.VerifyingKey{}
	vk.G1.Alpha = *alphaG1
	vk.G1.K = G1K
	vk.G2.Beta = *betaG2
	vk.G2.Gamma = *gammaG2
	vk.G2.Delta = *deltaG2

	if err := vk.Precompute(); err != nil {
		return nil, fmt.Errorf("failed to precompute verification key: %v", err)
	}
	return vk, nil
}

// Verify verifies the Gnark proof using the provided verification key and public inputs over BN254.
func (proof *GnarkProofBN254) Verify() (bool, error) {
	err := groth16_bn254.Verify(proof.Proof, proof.VerifyingKey, proof.PublicInputs)
	if err != nil {
		return false, fmt.Errorf("proof verification failed: %v", err)
	}
	return true, nil
}