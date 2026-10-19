# DAVINCI Circom

This repository includes the zkSnark circuits and cryptographic primitives that allow proving a valid vote in the [DAVINCI](https://davinci.vote) protocol, including the format of the vote itself and its encryption (ElGamal).

The circuits are optimized for the **BN254** curve and use **Poseidon** for hashing and **BabyJubJub** for ElGamal encryption.

 * **Ballot protocol** ([`ballot_protocol.circom`](./circuits/ballot_protocol.circom)): Unpacks the packed ballot mode and checks that the ballot is valid under those params (field limits, weights, quadratic cost, uniqueness).
 * **Ballot cipher** ([`ballot_cipher.circom`](./circuits/ballot_cipher.circom)): Encrypts the ballot fields using ElGamal on the BabyJubJub curve and checks if they match with the provided ones.
 * **Ballot proof** ([`ballot_proof.circom`](./circuits/ballot_proof.circom)): Checks the ballot and its encryption and calculates the vote ID. Every value a verifier needs is a public signal (71 for `BallotProof(16)`), in this order: `address`, `vote_id`, `process_id`, `packed_ballot_mode`, `encryption_pubkey[0..1]`, `weight`, then `c1.x, c1.y, c2.x, c2.y` of each of the 16 cipherfields. `test/public_order_test.go` pins the order against the compiled `.sym` file.

## BallotMode Packed Serialization (State Root)

To reduce on-chain hashing costs, ballot mode can be serialized into a single BN254 field element (247 bits / less than 31 bytes) and used directly as the ballot-mode leaf value (no extra Poseidon hash). This packed representation is only used for the **state root** leaf; the ballot protocol still consumes the full ballot mode fields directly.

### Fields

`groupSize` is a new ballot protocol parameter that must satisfy `groupSize <= numFields`.

### Bit Layout (LSB-first)

| Bit range (LSB..MSB) | Size | Field | Constraint |
| --- | --- | --- | --- |
| 0..7 | 8 | `numFields` | `< 2^8` |
| 8..15 | 8 | `groupSize` | `< 2^8`, `<= numFields` |
| 16 | 1 | `uniqueValues` | `0/1` |
| 17..24 | 8 | `costExponent` | `< 2^8` |
| 25..72 | 48 | `maxValue` | `< 2^48` |
| 73..120 | 48 | `minValue` | `< 2^48` |
| 121..183 | 63 | `maxValueSum` | `< 2^63` |
| 184..246 | 63 | `minValueSum` | `< 2^63` |

### Packing Formula

```
packed =
    numFields
  | (groupSize << 8)
  | (uniqueValues << 16)
  | (costExponent << 17)
  | (maxValue << 25)
  | (minValue << 73)
  | (maxValueSum << 121)
  | (minValueSum << 184)
```

Any value that exceeds its bit width makes the serialization invalid.

### State Root Leaf Usage

The state root leaf hashes use `processId`, `packedBallotMode`, and `censusOrigin` directly as Poseidon inputs (no 1‑element Poseidon). Inputs are interpreted modulo the BN254 scalar field.

## Circuit Constraints

The circuit is compiled with a fixed capacity of **16 voting fields**
(`BallotProof(16)` in [`ballot_proof.circom`](./circuits/ballot_proof.circom)).
Measured R1CS over BN254:

| Metric | Value |
| :--- | ---: |
| Constraints | 61,678 |
| Wires | 61,522 |
| Public inputs | 71 |
| Private inputs | 17 (`fields[16]`, `k`) |
| Labels | 343,524 |

The ElGamal encryption of the ballot fields (`BallotCipher`) dominates the
constraint count and scales roughly linearly with the field count; the ballot
mode checks (`CheckBallotMode`) and Vote ID hashing (`VoteIDChecker`) are
comparatively small. The shared encryption public key is validated once
(prime-order subgroup + non-identity) in `BallotCipher` rather than inside each
per-field `ElGamal` instance; hoisting that 253-bit variable-base scalar mul out
of the loop cut the circuit from 103,231 to 64,816 constraints (−37%). The
Groth16 setup reuses the `2^18` Powers of Tau (`ppot_0080_18.ptau`, 262,144 max
constraints), leaving ample headroom over the 64,816 constraints used.

### Artifact sizes

| Artifact | File | Size |
| :--- | :--- | ---: |
| Proving key | `ballot_proof_pkey.zkey` | 31.1 MiB |
| Witness generator | `ballot_proof.wasm` | 2.3 MiB |
| Verification key | `ballot_proof_vkey.json` | 15.4 KiB |

The proving key is the largest artifact a client needs: in-browser proving
(the webapp) downloads both the `.zkey` and the `.wasm` before it can generate
a proof.

### Development setup

The tracked zkey and verification key come from a development setup:
`prepare-circuit.sh` runs `snarkjs groth16 setup` on the Powers of Tau file and
then two `snarkjs zkey beacon` steps keyed by hashes committed in the script,
with circom pinned to 2.1.6. Every run reproduces the same bytes, and CI fails
when `sha256` of the verification key wire bytes differs from
`artifacts/DEV_VK_HASH`. The verification key carries `"setup": "dev"`.

Anyone can recompute this setup's toxic waste and forge proofs under it. The
dev key must never back a launched registry: the production ceremony replaces
the zkey, the verification key and `DEV_VK_HASH`.

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
