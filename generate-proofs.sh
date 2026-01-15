#!/bin/bash
set -e

# Check if an argument is provided
if [ -z "$1" ]; then
    echo "Usage: $0 <n_proofs> <path>"
    echo "  - n_proofs: the number of proofs to generate"
    echo "  - path (optional): the path to store the proofs, by default ./test/testdata"
    exit 1
fi

n_proofs=$1

# Determine absolute path for output
if [ -n "$2" ]; then
    if [[ "$2" = /* ]]; then
        abs_path="$2"
    else
        abs_path="$(cd "$(dirname "$2")"; pwd)/$(basename "$2")"
    fi
else
    abs_path="$PWD/test/testdata"
fi

# Ensure directory exists
mkdir -p "$abs_path"

echo "Generating $n_proofs proofs in $abs_path..."

for idx in $(seq 1 "$n_proofs"); do
    echo "Generating $idx of $n_proofs..."
    go test -timeout 30s -run ^TestBallotProof$ github.com/vocdoni/davinci-circom/test -v -count=1 -args -test-id="$idx" -persist -path="$abs_path" >/dev/null 2>&1
done

echo "All tests completed."
