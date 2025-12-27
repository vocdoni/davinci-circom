#!/bin/bash

# check if the circuit is provided and exists
CIRCUIT="$1"
if [ -z "$CIRCUIT" ]; then
    echo "Please provide the path to the circom circuit file"
    exit 1
fi

# if artifacts directory is not provided, use the default one
if [ -z "$2" ]; then
    ARTIFACTS_DIR="$PWD/artifacts"
fi
if [ ! -d "$ARTIFACTS_DIR" ]; then
    mkdir "$ARTIFACTS_DIR"
fi

# Create deps directory
DEPS_DIR="$PWD/deps"
if [ ! -d "$DEPS_DIR" ]; then
    mkdir "$DEPS_DIR"
fi

# check if npm is installed
if [ ! command -v npm &> /dev/null ]; then
    echo "npm is not installed"
    exit 1
fi

# check if cargo is installed
if [ ! command -v cargo &> /dev/null ]; then
    echo "rust is not installed"
    exit 1
fi

echo '{"name": "davinci-circom-circuits"}' > ./package.json

# Check/Install Circom
CIRCOM_BIN="$DEPS_DIR/circom/target/release/circom"
if [ ! -f "$CIRCOM_BIN" ]; then
    echo "circom not found, installing in $DEPS_DIR..."
    if [ ! -d "$DEPS_DIR/circom" ]; then
        git clone https://github.com/iden3/circom.git "$DEPS_DIR/circom"
    fi
    cd "$DEPS_DIR/circom"
    cargo build --release
    cd -
fi

# Check/Install SnarkJS (Custom fork with BLS12-377)
SNARKJS_DIR="$DEPS_DIR/snarkjs"
SNARKJS="node $SNARKJS_DIR/cli.js"

if [ ! -d "$SNARKJS_DIR" ]; then
    echo "snarkjs (p4u fork) not found, cloning..."
    git clone https://github.com/p4u/snarkjs.git "$SNARKJS_DIR"
    cd "$SNARKJS_DIR"
    git submodule update --init --recursive
    npm install
    cd -
fi

# install circomlib in local package
npm install circomlib

[ "$CIRCUIT" == "all" ] && {
  CIRCUIT=$(find test -name "*.circom")
}

for C in $CIRCUIT; do
  # compile the circuit
  echo "=> Compiling circuit $C"
  $CIRCOM_BIN $C --r1cs --wasm --sym --prime bls12377 -o $ARTIFACTS_DIR \
    -l ./circuits/lib/bls12377 \
    -l ./node_modules/circomlib/circuits \
    -l "$DEPS_DIR/circom-ecdsa/circuits"
  
  # check if ptau file exists, if not generate it for bls12377
  if [ ! -f "$ARTIFACTS_DIR/ptau" ]; then
      echo "Generating ptau file for bls12377..."
      $SNARKJS powersoftau new bls12377 17 $ARTIFACTS_DIR/ptau_0.ptau -v
      $SNARKJS powersoftau contribute $ARTIFACTS_DIR/ptau_0.ptau $ARTIFACTS_DIR/ptau_1.ptau --name="First contribution" -v -e="some random text"
      $SNARKJS powersoftau prepare phase2 $ARTIFACTS_DIR/ptau_1.ptau $ARTIFACTS_DIR/ptau.ptau -v
      mv $ARTIFACTS_DIR/ptau.ptau $ARTIFACTS_DIR/ptau
  fi
  
  # generate the trusted setup
  NAME=$(basename $C .circom)
  R1CS=$ARTIFACTS_DIR/$NAME.r1cs
  $SNARKJS groth16 setup $R1CS $ARTIFACTS_DIR/ptau $ARTIFACTS_DIR/$NAME\_pkey.zkey
  
  # export the verification key
  $SNARKJS zkey export verificationkey $ARTIFACTS_DIR/$NAME\_pkey.zkey $ARTIFACTS_DIR/$NAME\_vkey.json
  
  # mv wasm from $ARTIFACTS/$NAME_js/$NAME.wasm to $ARTIFACTS/$NAME.wasm
  if [ -f "$ARTIFACTS_DIR/$NAME\_js/$NAME.wasm" ]; then
    mv $ARTIFACTS_DIR/$NAME\_js/$NAME.wasm $ARTIFACTS_DIR/$NAME.wasm
  fi
done
  
# clean up
rm -rf ./node_modules package-lock.json package.json
