# DAVINCI Circom

This repository includes the zkSnark circuits and cryptographic primitives that allow proving a valid vote in the [DAVINCI](https://davinci.vote) protocol, including the format of the vote itself and its encryption (ElGamal).

The circuits are optimized for the **BN254** curve and use **Poseidon** for hashing and **BabyJubJub** for ElGamal encryption.

 * **Ballot checker** ([`ballot_checker.circom`](./circuits/ballot_checker.circom)): Checks that the ballot is valid under the params provided as inputs.
 * **Ballot cipher** ([`ballot_cipher.circom`](./circuits/ballot_cipher.circom)): Encrypts the ballot fields using ElGamal on the BabyJubJub curve and checks if they match with the provided ones.
 * **Ballot proof** ([`ballot_proof.circom`](./circuits/ballot_proof.circom)): Checks the ballot and its encryption, calculates the vote ID, and verifies the hash of all inputs using Poseidon MultiHash. It exposes `inputs_hash`, `address`, and `vote_id` as public signals.

## Circuit Constraints

Below are the constraint counts for the main circuits and components (configured with 8 voting fields):

| Circuit | Constraints (BN254) | Description |
| :--- | :--- | :--- |
| **BallotChecker** | 10,071 | Validates ballot logic (limits, weights, quadratic cost) |
| **BallotCipher** | 56,104 | ElGamal encryption of 8 fields on BabyJubJub |
| **VoteIDChecker** | 518 | Computes and verifies Vote ID (Poseidon hash) |
| **BallotProof** | **68,721** | **Total** (Includes all components + Input Hashing) |

## Usage

Use the provided `Makefile` to handle dependencies, compilation, and testing:

*   **`make`**: Prepares the circuits and runs the full Go test suite.
*   **`make prepare`**: Compiles the default circuits and installs necessary tools (`circom`, `snarkjs`).
*   **`make test`**: Runs the Go test suite (includes native verification and aggregation tests).
*   **`make webapp`**: Starts the Proof Generator React Webapp on `0.0.0.0:5173`.

## Circom2Gnark

The [`circom2gnark`](./circom2gnark) package provides utilities to bridge Circom and Gnark ecosystems for **BN254**. It enables converting Circom/SnarkJS proofs into Gnark-compatible formats for recursive verification inside BN254 circuits using emulated arithmetic (`std/algebra/emulated/sw_bn254`).

## Requirements

 * [Go](https://go.dev/) (1.22+)
 * [Node & NPM](https://nodejs.org/)
 * [Rust](https://www.rust-lang.org/) (Required for some dependencies like `circom` if compiled from source)