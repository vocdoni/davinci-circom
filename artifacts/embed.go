package artifacts

import _ "embed"

var (
	// BallotProofWasm contains the ballot proof Circom circuit compiled to WASM.
	//
	//go:embed ballot_proof.wasm
	BallotProofWasm []byte

	// BallotProofProvingKey contains the Groth16 proving key for the ballot proof circuit.
	//
	//go:embed ballot_proof_pkey.zkey
	BallotProofProvingKey []byte

	// BallotProofVerificationKey contains the Groth16 verification key for the ballot proof circuit.
	//
	//go:embed ballot_proof_vkey.json
	BallotProofVerificationKey []byte
)
