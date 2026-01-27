#!/bin/bash
set -e

# Create deps directory if not exists
if [ ! -d "deps" ]; then
    mkdir "deps"
fi

# Determine circom binary
if command -v circom &> /dev/null; then
    CIRCOM_BIN="circom"
elif [ -f "./deps/circom" ]; then
    CIRCOM_BIN="./deps/circom"
else
    echo "Downloading circom..."
    wget -q https://github.com/iden3/circom/releases/download/v2.1.6/circom-linux-amd64 -O "./deps/circom"
    chmod +x "./deps/circom"
    CIRCOM_BIN="./deps/circom"
fi

$CIRCOM_BIN --version > /dev/null
if [ $? -ne 0 ]; then
   echo "Circom check failed"
   exit 1
fi

# Artifacts dir
if [ -z "$2" ]; then
    ARTIFACTS_DIR="$PWD/artifacts"
fi
if [ ! -d "$ARTIFACTS_DIR" ]; then
    mkdir "$ARTIFACTS_DIR"
fi

# Ensure dependencies are installed
if [ ! -d "node_modules" ]; then
    npm install
fi

SNARKJS="./node_modules/.bin/snarkjs"

# Circuit to compile
CIRCUIT="${1:-circuits/ballot_proof.circom}"

for C in $CIRCUIT; do
  NAME=$(basename $C .circom)
  echo "=> Compiling circuit $C ($NAME)"
  
  # Compile (defaults to bn128)
  $CIRCOM_BIN $C --r1cs --wasm --sym -o $ARTIFACTS_DIR \
    -l ./circuits \
    -l ./node_modules
  
  # PTAU Generation (bn128)
  # Check if ptau exists
  PTAU_FILE="$ARTIFACTS_DIR/ptau_final.ptau"
  if [ ! -f "$PTAU_FILE" ]; then
      echo "Downloading ptau file..."
      wget --progress=dot:giga https://pse-trusted-setup-ppot.s3.eu-central-1.amazonaws.com/pot28_0080/ppot_0080_18.ptau -O $PTAU_FILE
  fi
  
  # Setup (Groth16)
  R1CS="$ARTIFACTS_DIR/$NAME.r1cs"
  ZKEY="$ARTIFACTS_DIR/${NAME}_pkey.zkey"
  VKEY="$ARTIFACTS_DIR/${NAME}_vkey.json"
  
  echo "=> Setup Groth16 for $NAME"
  $SNARKJS groth16 setup $R1CS $PTAU_FILE $ZKEY
  
  # Export Verification Key
  $SNARKJS zkey export verificationkey $ZKEY $VKEY
  
  # Move WASM
  WASM_DIR="$ARTIFACTS_DIR/${NAME}_js"
  if [ -f "$WASM_DIR/$NAME.wasm" ]; then
      cp "$WASM_DIR/$NAME.wasm" "$ARTIFACTS_DIR/$NAME.wasm"
  fi
done