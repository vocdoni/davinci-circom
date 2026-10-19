# Ballot proof trusted setup: pre-production ceremony

Phase 2 of the Groth16 setup of `circuits/ballot_proof.circom` (`BallotProof(16)`, 71 public
inputs), run on 2026-10-19 for the pre-production deployment. It replaces the deterministic
development key of v1.1.0. A public multi-party ceremony replaces this key before public production.

| Input | sha256 |
|---|---|
| `ballot_proof.r1cs` (circom 2.1.6) | `973249452445771f9c5f6792488f9f58da560987c00a71ed9f45024e54d7d199` |
| `ptau_final.ptau` (`ppot_0080_18.ptau`, PSE perpetual powers of tau) | `9693220206afab749e3d88d4ab5fdf5d36120ea102e7e587ccea0e7a5208e711` |

snarkjs 0.7.6 circuit hash: `cd40e05a63677c7c65de7416aa32f98d3464a61dcae5a3acb8cc2664214b20ee302e25d9d6d9efc446115144cc2999818bf53ef3603a947497b54d141277421c`

| # | Contribution | Hash |
|---|---|---|
| 1 | davinci pre-production contribution 1 (OS entropy) | `42c3b427a54491d692f95341be0e337ed3fa96eb5f2415b04a993eb19f3616a44d1b079a4d251cfab5846e7d21321dbe8abb64b147a9367876fbbf245950d34b` |
| 2 | davinci pre-production contribution 2 (OS entropy) | `f87935a72e8275d54f29694ba83ea679df7efec821f29d0bb92a81c3f4d10f6b846ccddf9492755a0f31bc044de4ea30063876ad1e613494004cf7336d0111d0` |
| 3 | davinci pre-production contribution 3 (OS entropy) | `ecf88bffb23b63fda3342280c179fb28acc349b3d35a02a5172a45a0aff95e8fb96d232d1fc650bfd14e888bac4b7d9270bca8de45da45e192691b9df87a1728` |
| 4 | Final beacon: Ethereum mainnet block 26227024, hash `0x7f68d2c87e0f3c52be43d8487eafae6d7d9aeb5fdc1b9ba02841dca0a669b4da`, 2^10 iterations | `de7de24997ded43b6c62cb7f05c9f51a6ea9c50a327abd0af94ec0666b2e118ea1bf8ea0c0ddfb48e9595cc149bfa9277ebf57781d5a65b9f8d019db166e0dbf` |

Outputs:

| File | sha256 |
|---|---|
| `artifacts/ballot_proof_pkey.zkey` | `e634798d1a4bca81c743348f654e7cd8d458bd396065dbca1cfc4a0c6a90b084` |
| `artifacts/ballot_proof_vkey.json` (`"setup": "ceremony"`) | `4a05045a22a5019ca6cff8057b77c9968856175f9b20705e86925b6f12112f4b` |

VK wire hash (`artifacts/VK_HASH`, the registry's `ballotVKHash`): `7caffddcd7ea38439cbb45789b810d8eafceca65cff93dbeaae409b2bf64e219`

Check it yourself:

```bash
./prepare-circuit.sh            # compiles the circuit and runs the check below
npx snarkjs zkey verify artifacts/ballot_proof.r1cs artifacts/ptau_final.ptau artifacts/ballot_proof_pkey.zkey
```

`zkey verify` replays every contribution against the r1cs and the ptau and prints the hashes above.
