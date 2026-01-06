# ZK Proof Generator Webapp

This is a simple React application to generate and verify zkSNARK proofs for the `ballot_proof` circuit using `snarkjs`.

## Setup

1.  **Install dependencies:**
    ```bash
    npm install
    ```

2.  **Start Development Server:**
    ```bash
    npm run dev
    ```
    Open the URL (usually `http://localhost:5173`) in your browser.

## Logic

-   **Generate Proof:** Fetches `input.json`, `ballot_proof.wasm`, and `ballot_proof_pkey.zkey` from the `public/` directory. Uses `snarkjs.groth16.fullProve` to generate the proof and public signals.
-   **Verify Proof:** Fetches `ballot_proof_vkey.json` and uses `snarkjs.groth16.verify` to check the validity of the generated proof against the public signals.

## Assets

The artifacts (`.wasm`, `.zkey`, `.json`) are copied from the project's `artifacts/` directory. If you rebuild the circuits, update these files.