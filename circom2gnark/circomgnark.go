// circomgnark package provides utilities to convert between Circom and Gnark
// proof formats, allowing for verification of zkSNARK proofs created with
// Circom and SnarkJS to be used within the Gnark framework.
// It includes functions to convert Circom proofs and verification keys to
// Gnark over the BN254 curve, and to verify these proofs using Gnark's
// verification functions. It also provides a way to handle recursive proofs
// and placeholders for recursive circuits.
package circom2gnark

// Circom2GnarkProofForRecursionBN254 converts a Circom BN254 proof into a Gnark recursion proof with fixed VK.
func Circom2GnarkProofForRecursionBN254(vkey []byte, rawCircomProof, rawPubSignals string) (*GnarkRecursionProofBN254, error) {
	return Circom2GnarkProofForRecursionBN254WithVK(vkey, rawCircomProof, rawPubSignals, true)
}

// Circom2GnarkProofForRecursionBN254WithVK converts a Circom BN254 proof into a Gnark recursion proof,
// allowing the caller to decide whether the verifying key is fixed in-circuit.
func Circom2GnarkProofForRecursionBN254WithVK(vkey []byte, rawCircomProof, rawPubSignals string, fixedVk bool) (*GnarkRecursionProofBN254, error) {
	circomProof, circomPubSignals, err := UnmarshalCircom(rawCircomProof, rawPubSignals)
	if err != nil {
		return nil, err
	}
	circomVerificationKey, err := UnmarshalCircomVerificationKeyJSON(vkey)
	if err != nil {
		return nil, err
	}
	return circomProof.ToGnarkRecursionBN254(circomVerificationKey, circomPubSignals, fixedVk)
}

// Circom2GnarkPlaceholderBN254 creates placeholders for BN254 recursion circuits with fixed VK.
func Circom2GnarkPlaceholderBN254(vkey []byte, nInputs int) (*GnarkRecursionPlaceholdersBN254, error) {
	return Circom2GnarkPlaceholderBN254WithVK(vkey, nInputs, true)
}

// Circom2GnarkPlaceholderBN254WithVK creates placeholders for BN254 recursion circuits and lets caller choose fixed VK.
func Circom2GnarkPlaceholderBN254WithVK(vkey []byte, nInputs int, fixedVk bool) (*GnarkRecursionPlaceholdersBN254, error) {
	gnarkVKeyData, err := UnmarshalCircomVerificationKeyJSON(vkey)
	if err != nil {
		return nil, err
	}
	return PlaceholdersForRecursionBN254(gnarkVKeyData, nInputs, fixedVk)
}

// VerifyCircomProofBN254 verifies a Circom BN254 proof natively using gnark-crypto.
func VerifyCircomProofBN254(vkey []byte, rawProof string, pubSignals []string) (bool, error) {
	circomProof, circomPubSignals, err := UnmarshalCircom(rawProof, stringMustJSON(pubSignals))
	if err != nil {
		return false, err
	}
	circomVerificationKey, err := UnmarshalCircomVerificationKeyJSON(vkey)
	if err != nil {
		return false, err
	}
	gnarkProof, err := circomProof.ToGnarkProofBN254(circomVerificationKey, circomPubSignals)
	if err != nil {
		return false, err
	}
	return gnarkProof.Verify()
}