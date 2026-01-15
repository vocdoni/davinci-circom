package circom2gnark

import (
	"fmt"
	"math/big"

	"github.com/consensys/gnark/std/math/emulated"
	recursion "github.com/consensys/gnark/std/recursion/groth16"

	groth16_bn254 "github.com/consensys/gnark/backend/groth16/bn254"
	"github.com/consensys/gnark/std/algebra/emulated/sw_bn254"
)

// ToGnarkRecursionBN254 converts a Circom proof (BN254) to the Gnark recursion proof format.
func (circomProof *CircomProof) ToGnarkRecursionBN254(circomVk *CircomVerificationKey,
	circomPublicSignals []string, fixedVk bool,
) (*GnarkRecursionProofBN254, error) {
	publicInputs, err := ConvertPublicInputsBN254(circomPublicSignals)
	if err != nil {
		return nil, err
	}
	gnarkProof, err := circomProof.ToGnarkBN254()
	if err != nil {
		return nil, err
	}
	recursionProof, err := recursion.ValueOfProof[sw_bn254.G1Affine, sw_bn254.G2Affine](gnarkProof)
	if err != nil {
		return nil, fmt.Errorf("failed to convert proof to recursion proof: %w", err)
	}

	gnarkVk, err := circomVk.ToGnarkBN254()
	if err != nil {
		return nil, err
	}
	publicInputElementsEmulated := make([]emulated.Element[sw_bn254.ScalarField], len(publicInputs))
	for i, input := range publicInputs {
		bigIntValue := input.BigInt(new(big.Int))
		publicInputElementsEmulated[i] = emulated.ValueOf[sw_bn254.ScalarField](bigIntValue)
	}
	assignments := &GnarkRecursionProofBN254{
		Proof: recursionProof,
		PublicInputs: recursion.Witness[sw_bn254.ScalarField]{
			Public: publicInputElementsEmulated,
		},
	}
	if !fixedVk {
		recursionVk, err := recursion.ValueOfVerifyingKey[sw_bn254.G1Affine, sw_bn254.G2Affine, sw_bn254.GTEl](gnarkVk)
		if err != nil {
			return nil, fmt.Errorf("failed to convert verification key to recursion verification key: %w", err)
		}
		assignments.Vk = recursionVk
	}
	return assignments, nil
}

// PlaceholdersForRecursionBN254 creates placeholders for BN254 recursion circuits.
func PlaceholdersForRecursionBN254(circomVk *CircomVerificationKey,
	nPublicInputs int, fixedVk bool,
) (*GnarkRecursionPlaceholdersBN254, error) {
	gnarkVk, err := circomVk.ToGnarkBN254()
	if err != nil {
		return nil, err
	}
	return createPlaceholdersForRecursionBN254(gnarkVk, nPublicInputs, fixedVk)
}

func createPlaceholdersForRecursionBN254(gnarkVk *groth16_bn254.VerifyingKey,
	nPublicInputs int, fixedVk bool,
) (*GnarkRecursionPlaceholdersBN254, error) {
	if gnarkVk == nil || nPublicInputs < 0 {
		return nil, fmt.Errorf("invalid inputs to create placeholders for recursion")
	}
	placeholderVk, err := recursion.ValueOfVerifyingKeyFixed[sw_bn254.G1Affine, sw_bn254.G2Affine, sw_bn254.GTEl](gnarkVk)
	if err != nil {
		return nil, fmt.Errorf("failed to convert verification key to recursion verification key: %w", err)
	}
	placeholderWitness := recursion.Witness[sw_bn254.ScalarField]{
		Public: make([]emulated.Element[sw_bn254.ScalarField], nPublicInputs),
	}
	placeholderProof := recursion.Proof[sw_bn254.G1Affine, sw_bn254.G2Affine]{}

	placeholders := &GnarkRecursionPlaceholdersBN254{
		Vk:      placeholderVk,
		Witness: placeholderWitness,
		Proof:   placeholderProof,
	}
	if !fixedVk {
		placeholders.Vk.G1.K = make([]sw_bn254.G1Affine, len(placeholders.Vk.G1.K))
	}
	return placeholders, nil
}

// ToGnarkProofBN254 converts to non-recursive Gnark proof over BN254.
func (circomProof *CircomProof) ToGnarkProofBN254(circomVk *CircomVerificationKey,
	circomPublicSignals []string,
) (*GnarkProofBN254, error) {
	publicInputs, err := ConvertPublicInputsBN254(circomPublicSignals)
	if err != nil {
		return nil, err
	}
	proof, err := circomProof.ToGnarkBN254()
	if err != nil {
		return nil, err
	}
	vk, err := circomVk.ToGnarkBN254()
	if err != nil {
		return nil, err
	}
	return &GnarkProofBN254{
		Proof:        proof,
		VerifyingKey: vk,
		PublicInputs: publicInputs,
	}, nil
}

// ToGnarkRecursionProofBN254 is a helper to convert to recursion proof with fixed vk.
func (circomProof *CircomProof) ToGnarkRecursionProofBN254(circomVk *CircomVerificationKey,
	circomPublicSignals []string,
) (*GnarkRecursionProofBN254, error) {
	return circomProof.ToGnarkRecursionBN254(circomVk, circomPublicSignals, true)
}