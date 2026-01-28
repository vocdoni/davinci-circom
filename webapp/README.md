# ZK Proof Generator Webapp

A React application to generate and verify zkSNARK proofs for the DAVINCI `ballot_proof` circuit using `snarkjs`.

## Setup

### From the repository root (recommended)

```bash
# Start development server with artifacts
make webapp
```

### Manual setup

1. Copy circuit artifacts from `artifacts/` to `public/`:
   ```bash
   cp ../artifacts/ballot_proof.wasm public/
   cp ../artifacts/ballot_proof_pkey.zkey public/
   cp ../artifacts/ballot_proof_vkey.json public/
   ```

2. Install dependencies and start:
   ```bash
   npm install
   npm run dev
   ```

Open the URL (usually `http://localhost:5173`) in your browser.

## How it works

- **Generate Proof:** Uses `@vocdoni/davinci-circom` to generate circuit inputs, then fetches the WASM and zkey files to generate a Groth16 proof using snarkjs.
- **Verify Proof:** Fetches `ballot_proof_vkey.json` and uses `snarkjs.groth16.verify` to check the validity of the generated proof.

## Circuit Artifacts

The circuit artifacts (`.wasm`, `.zkey`, `.json`) are stored in the repository's `artifacts/` directory and copied to `public/` at build time:

- `ballot_proof.wasm` - The compiled circuit
- `ballot_proof_pkey.zkey` - The proving key
- `ballot_proof_vkey.json` - The verification key

These files are **not committed** to `webapp/public/` - they are copied by the Makefile or CI pipeline.