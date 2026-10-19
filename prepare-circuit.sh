#!/bin/bash
# Compile a circuit. For ballot_proof, verify the committed ceremony key
# (CEREMONY.md) against the fresh r1cs and the ptau; for other circuits (the
# test circuits) run a development Groth16 setup.
# DEV_SETUP=1 writes the deterministic dev key for ballot_proof to
# artifacts/dev/ instead.
# Usage: [DEV_SETUP=1] ./prepare-circuit.sh [circuit.circom ...] [artifacts-dir]
set -euo pipefail

# The r1cs/wasm (and the dev zkey and VK) are reproducible byte for byte only with this exact
# circom build: circom 2.2.x compiles BallotProof(16) to a different R1CS.
CIRCOM_VERSION="2.1.6"
CIRCOM_SHA256="f3958483caaaa0cdd3912df5049e2e635eab4d09b9a66807be9633d547859f12"
PTAU_URL="https://pse-trusted-setup-ppot.s3.eu-central-1.amazonaws.com/pot28_0080/ppot_0080_18.ptau"
PTAU_SHA256="9693220206afab749e3d88d4ab5fdf5d36120ea102e7e587ccea0e7a5208e711"

# Development phase 2 (test circuits, and ballot_proof under DEV_SETUP=1). snarkjs `zkey contribute` mixes 64 OS-random bytes into
# its entropy, so both steps are `zkey beacon`s keyed by these committed
# values: CI rebuilds the same key, and anyone can forge proofs under it. A
# dev key must never back a launched registry.
DEV_CONTRIBUTION_HASH="8b4f5f29cb130ba8b09490c05907326bbe3b35b3d3614fd4ba67ebc377d4261d" # sha256("davinci-circom dev contribution v1")
DEV_BEACON_HASH="fde8fea177bf2b49998342e09d5da6a0253259b3b4e2ba6e0a0c5d115e5393d9"       # sha256("davinci-circom dev beacon v1")
DEV_BEACON_ITERATIONS=10

mkdir -p deps
CIRCOM_BIN="./deps/circom"
if ! echo "$CIRCOM_SHA256  $CIRCOM_BIN" | sha256sum -c --quiet 2>/dev/null; then
    echo "Downloading circom $CIRCOM_VERSION..."
    wget -q "https://github.com/iden3/circom/releases/download/v$CIRCOM_VERSION/circom-linux-amd64" -O "$CIRCOM_BIN"
    chmod +x "$CIRCOM_BIN"
    echo "$CIRCOM_SHA256  $CIRCOM_BIN" | sha256sum -c --quiet
fi

ARTIFACTS_DIR="${2:-$PWD/artifacts}"
mkdir -p "$ARTIFACTS_DIR"

if [ ! -d "node_modules" ]; then
    npm install
fi
SNARKJS="./node_modules/.bin/snarkjs"

PTAU_FILE="$ARTIFACTS_DIR/ptau_final.ptau"
if [ ! -f "$PTAU_FILE" ]; then
    echo "Downloading ptau file..."
    wget --progress=dot:giga "$PTAU_URL" -O "$PTAU_FILE"
fi
echo "$PTAU_SHA256  $PTAU_FILE" | sha256sum -c --quiet

CIRCUIT="${1:-circuits/ballot_proof.circom}"

for C in $CIRCUIT; do
    NAME=$(basename "$C" .circom)
    echo "=> Compiling circuit $C ($NAME)"
    "$CIRCOM_BIN" "$C" --r1cs --wasm --sym -o "$ARTIFACTS_DIR" -l ./circuits -l ./node_modules

    R1CS="$ARTIFACTS_DIR/$NAME.r1cs"
    ZKEY="$ARTIFACTS_DIR/${NAME}_pkey.zkey"
    VKEY="$ARTIFACTS_DIR/${NAME}_vkey.json"
    ZKEY0="$ARTIFACTS_DIR/${NAME}_0000.zkey"
    ZKEY1="$ARTIFACTS_DIR/${NAME}_0001.zkey"

    if [ "$NAME" = "ballot_proof" ] && [ "${DEV_SETUP:-0}" != "1" ]; then
        # Committed ceremony key (CEREMONY.md): verify it, never overwrite it.
        echo "=> Verifying the committed ceremony key for $NAME"
        $SNARKJS zkey verify "$R1CS" "$PTAU_FILE" "$ZKEY"
        CHECK_VKEY="$ARTIFACTS_DIR/${NAME}_vkey_check.json"
        $SNARKJS zkey export verificationkey "$ZKEY" "$CHECK_VKEY"
        # The exported key must equal the committed one (ignoring the "setup"
        # label) and carry a phase-2 contribution (delta != gamma).
        node -e '
            const fs = require("fs");
            const read = (p) => JSON.parse(fs.readFileSync(p, "utf8"));
            const exported = read(process.argv[1]);
            const { setup, ...committed } = read(process.argv[2]);
            if (JSON.stringify(exported.vk_delta_2) === JSON.stringify(exported.vk_gamma_2)) {
                console.error("refusing a VK without a phase-2 contribution (delta == gamma)");
                process.exit(1);
            }
            if (JSON.stringify(exported) !== JSON.stringify(committed)) {
                console.error("committed vkey does not match the key exported from the committed zkey");
                process.exit(1);
            }
            console.log("committed vkey matches the zkey (setup: " + setup + ")");
        ' "$CHECK_VKEY" "$VKEY"
        rm -f "$CHECK_VKEY"
    else
        KEY_DIR="$ARTIFACTS_DIR"
        if [ "$NAME" = "ballot_proof" ]; then
            # Development key: separate directory, never over the committed key.
            KEY_DIR="$ARTIFACTS_DIR/dev"
            mkdir -p "$KEY_DIR"
            ZKEY="$KEY_DIR/${NAME}_pkey.zkey"
            VKEY="$KEY_DIR/${NAME}_vkey.json"
            ZKEY0="$KEY_DIR/${NAME}_0000.zkey"
            ZKEY1="$KEY_DIR/${NAME}_0001.zkey"
        fi

        echo "=> Groth16 dev setup for $NAME"
        $SNARKJS groth16 setup "$R1CS" "$PTAU_FILE" "$ZKEY0"
        $SNARKJS zkey beacon "$ZKEY0" "$ZKEY1" "$DEV_CONTRIBUTION_HASH" "$DEV_BEACON_ITERATIONS" -n="dev contribution"
        $SNARKJS zkey beacon "$ZKEY1" "$ZKEY" "$DEV_BEACON_HASH" "$DEV_BEACON_ITERATIONS" -n="dev beacon"
        rm -f "$ZKEY0" "$ZKEY1"
        $SNARKJS zkey verify "$R1CS" "$PTAU_FILE" "$ZKEY"

        $SNARKJS zkey export verificationkey "$ZKEY" "$VKEY"
        # Label the key and refuse one without a phase-2 contribution (delta == gamma).
        node -e '
            const fs = require("fs");
            const path = process.argv[1];
            const vk = JSON.parse(fs.readFileSync(path, "utf8"));
            if (JSON.stringify(vk.vk_delta_2) === JSON.stringify(vk.vk_gamma_2)) {
                console.error("refusing a VK without a phase-2 contribution (delta == gamma)");
                process.exit(1);
            }
            fs.writeFileSync(path, JSON.stringify({ setup: "dev", ...vk }, null, 1) + "\n");
        ' "$VKEY"

        $SNARKJS zkey export solidityverifier "$ZKEY" "$KEY_DIR/${NAME}_verifier.sol"
    fi

    WASM_DIR="$ARTIFACTS_DIR/${NAME}_js"
    if [ -f "$WASM_DIR/$NAME.wasm" ]; then
        cp "$WASM_DIR/$NAME.wasm" "$ARTIFACTS_DIR/$NAME.wasm"
    fi
done
