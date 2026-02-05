pragma circom 2.1.0;

include "circomlib/circuits/poseidon.circom";
include "./lib/multiposeidon.circom";

// StateProof recomputes the initial state root from the process inputs.
// It mirrors the arbo SMT construction for the fixed keys:
//   0 (process_id), 2 (ballot_mode), 3 (encryption_key),
//   4 (results_add), 5 (results_sub), 6 (census_origin).
template StateProof() {
    // Public inputs
    signal input state_root;
    signal input process_id;
    signal input census_origin;
    signal input num_fields;
    signal input unique_values;
    signal input max_value;
    signal input min_value;
    signal input max_value_sum;
    signal input min_value_sum;
    signal input cost_exponent;
    signal input cost_from_weight;
    signal input encryption_pubkey[2];

    // Hash leaf values with MultiPoseidon (same as Go/TS HashBigInts)
    component processHasher = Poseidon(1);
    processHasher.inputs[0] <== process_id;

    component ballotModeHasher = Poseidon(8);
    ballotModeHasher.inputs[0] <== num_fields;
    ballotModeHasher.inputs[1] <== unique_values;
    ballotModeHasher.inputs[2] <== max_value;
    ballotModeHasher.inputs[3] <== min_value;
    ballotModeHasher.inputs[4] <== max_value_sum;
    ballotModeHasher.inputs[5] <== min_value_sum;
    ballotModeHasher.inputs[6] <== cost_exponent;
    ballotModeHasher.inputs[7] <== cost_from_weight;

    component encKeyHasher = Poseidon(2);
    encKeyHasher.inputs[0] <== encryption_pubkey[0];
    encKeyHasher.inputs[1] <== encryption_pubkey[1];

    component censusHasher = Poseidon(1);
    censusHasher.inputs[0] <== census_origin;

    // Results add/sub are zero ballots at initialization.
    // Each ciphertext is (0,1,0,1) in reduced twisted Edwards.
    component zeroBallotHasher = MultiPoseidon(32);
    for (var i = 0; i < 8; i++) {
        zeroBallotHasher.in[i * 4 + 0] <== 0;
        zeroBallotHasher.in[i * 4 + 1] <== 1;
        zeroBallotHasher.in[i * 4 + 2] <== 0;
        zeroBallotHasher.in[i * 4 + 3] <== 1;
    }

    // Leaf hashes: Poseidon(key, value_hash, 1)
    component leafProcess = Poseidon(3);
    leafProcess.inputs[0] <== 0;
    leafProcess.inputs[1] <== processHasher.out;
    leafProcess.inputs[2] <== 1;

    component leafBallotMode = Poseidon(3);
    leafBallotMode.inputs[0] <== 2;
    leafBallotMode.inputs[1] <== ballotModeHasher.out;
    leafBallotMode.inputs[2] <== 1;

    component leafEncKey = Poseidon(3);
    leafEncKey.inputs[0] <== 3;
    leafEncKey.inputs[1] <== encKeyHasher.out;
    leafEncKey.inputs[2] <== 1;

    component leafResultsAdd = Poseidon(3);
    leafResultsAdd.inputs[0] <== 4;
    leafResultsAdd.inputs[1] <== zeroBallotHasher.out;
    leafResultsAdd.inputs[2] <== 1;

    component leafResultsSub = Poseidon(3);
    leafResultsSub.inputs[0] <== 5;
    leafResultsSub.inputs[1] <== zeroBallotHasher.out;
    leafResultsSub.inputs[2] <== 1;

    component leafCensus = Poseidon(3);
    leafCensus.inputs[0] <== 6;
    leafCensus.inputs[1] <== censusHasher.out;
    leafCensus.inputs[2] <== 1;

    // Compressed SMT root for keys {0,2,3,4,5,6} (LSB-first)
    component nodeA0 = Poseidon(2);
    nodeA0.inputs[0] <== leafProcess.out;
    nodeA0.inputs[1] <== leafResultsAdd.out;

    component nodeA1 = Poseidon(2);
    nodeA1.inputs[0] <== leafBallotMode.out;
    nodeA1.inputs[1] <== leafCensus.out;

    component nodeA = Poseidon(2);
    nodeA.inputs[0] <== nodeA0.out;
    nodeA.inputs[1] <== nodeA1.out;

    component nodeB = Poseidon(2);
    nodeB.inputs[0] <== leafResultsSub.out;
    nodeB.inputs[1] <== leafEncKey.out;

    component rootHasher = Poseidon(2);
    rootHasher.inputs[0] <== nodeA.out;
    rootHasher.inputs[1] <== nodeB.out;

    rootHasher.out === state_root;
}

component main {public [
    state_root,
    process_id,
    census_origin,
    num_fields,
    unique_values,
    max_value,
    min_value,
    max_value_sum,
    min_value_sum,
    cost_exponent,
    cost_from_weight,
    encryption_pubkey
]} = StateProof();
