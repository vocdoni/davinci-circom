# Ballot proof trusted setup: pre-production ceremony

Phase 2 of the Groth16 setup of `circuits/ballot_proof.circom` (`BallotProof(16)`, 71 public
inputs), run on 2026-10-20 for the pre-production deployment. It replaces the 2026-10-19 key of
v1.2.0, whose circuit changed (89-bit budget comparators, strict vote-id bits, constant
subgroup order). A public multi-party ceremony replaces this key before public production.

| Input | sha256 |
|---|---|
| `ballot_proof.r1cs` (circom 2.1.6) | `07cacd88e84229a1d563a2f88707f24814feb17c1e8788016dbcc672250ee120` |
| `ptau_final.ptau` (`ppot_0080_18.ptau`, PSE perpetual powers of tau) | `9693220206afab749e3d88d4ab5fdf5d36120ea102e7e587ccea0e7a5208e711` |

snarkjs 0.7.6 circuit hash: `9577afe7efc03ac3551b9ce4068cec3a3adb4b5811f888cad6ecbdb11b932c3de513c1b524473f1ac513406eda6a012d0147c1aa0cdceb111a6d23ddd865c67d`

| # | Contribution | Hash |
|---|---|---|
| 1 | davinci pre-production contribution 1 (OS entropy) | `2f2f53a27928cf96b4a4b07829a9c5d8ea2235c1e91f4ffab436493cb50fa76da6ed1bc6407ef04f3760ba5a025aa74332a2773fb151de638152ff195dd85eea` |
| 2 | davinci pre-production contribution 2 (OS entropy) | `bd4f25d609e7c74b43afafcad2c036b4b6b39062a9f6fe14f45f10d562c8ea90c89215e208d3bf82e899ec54f217ce35efee9d200e6175beaaf244ce7f961831` |
| 3 | davinci pre-production contribution 3 (OS entropy) | `7d2a69289fa46a8828339c47aac7b4bbb60d4ca2c0a09faa94c7cf9d1c3e67f532fb19a4216b60bd365e6338a3451e4097482e9353a3afacb1a52d7e310b3d87` |
| 4 | Final beacon: Ethereum mainnet block 26233977, hash `0xe4a05281a172b26aca444fea3e945a306896a469e8e808383bb98d59da846d3a`, 2^10 iterations | `748c2ef64467ba667e089aa6dfd2185a73ab5f6ff39add2e4a3b13c0058e59ca07b794c60a5420bdb90ffa73b2342ab8fc32303e00c674834450db96f93086e9` |

Outputs:

| File | sha256 |
|---|---|
| `artifacts/ballot_proof_pkey.zkey` | `1c17aedc4021d717f464dee89a6b8ede9fe1799e7e308f776ee31ca6933fd2c0` |
| `artifacts/ballot_proof_vkey.json` (`"setup": "ceremony"`) | `d2d36491e4b2c69e36199976b4b124334b4cb683577510f9ddb1bc2620f3f248` |
| `artifacts/ballot_proof.wasm` | `05df6ff4b6e9d914f7125674b18ee57bf106d3fc5b449e2501b3eaa97f099fcc` |

VK wire hash (`artifacts/VK_HASH`, the registry's `ballotVKHash`): `67e8e6b47ea32cf144d6e72886f02b95ed068b157f9d4ccc8e97f335858e4963`

Check it yourself:

```bash
./prepare-circuit.sh            # compiles the circuit and runs the check below
npx snarkjs zkey verify artifacts/ballot_proof.r1cs artifacts/ptau_final.ptau artifacts/ballot_proof_pkey.zkey
```

`zkey verify` replays every contribution against the r1cs and the ptau and prints the hashes above.
