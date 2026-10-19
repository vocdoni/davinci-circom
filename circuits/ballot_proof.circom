pragma circom 2.1.0;

include "circomlib/circuits/bitify.circom";

include "ballot_protocol.circom";
include "ballot_cipher.circom";

include "./lib/vote_id.circom";

// BallotProof is the circuit to prove a valid vote.
// The vote is valid if it meets the Ballot Protocol requirements, if the
// encrypted vote provided matches the raw vote encrypted in this circuit, and
// if the vote ID derives from the process ID, the address and k.
//
// snarkjs numbers public signals by declaration order, not by the order of
// the `public` list in `main`, so the public inputs are declared first and in
// the public-input layout (n = 7 + 4 * n_fields, 71 for BallotProof(16)):
//   0 address, 1 vote_id, 2 process_id, 3 packed_ballot_mode,
//   4 encryption_pubkey[0], 5 encryption_pubkey[1], 6 weight,
//   7 + 4f + (0, 1, 2, 3) = cipherfields[f][0][0], [f][0][1], [f][1][0], [f][1][1].
// test/public_order_test.go pins this order against the compiled .sym file.
template BallotProof(n_fields) {
    // Public inputs, in layout order.
    signal input address;
    signal input vote_id;
    signal input process_id;
    signal input packed_ballot_mode;
    signal input encryption_pubkey[2];
    signal input weight;
    signal input cipherfields[n_fields][2][2];
    // Private inputs.
    signal input fields[n_fields];
    signal input k;

    component unpack = UnpackBallotMode();
    unpack.packed <== packed_ballot_mode;

    signal num_fields;
    signal group_size;
    signal unique_values;
    signal cost_exponent;
    signal max_value;
    signal min_value;
    signal max_value_sum;
    signal min_value_sum;

    num_fields <== unpack.num_fields;
    group_size <== unpack.group_size;
    unique_values <== unpack.unique_values;
    cost_exponent <== unpack.cost_exponent;
    max_value <== unpack.max_value;
    min_value <== unpack.min_value;
    max_value_sum <== unpack.max_value_sum;
    min_value_sum <== unpack.min_value_sum;

    // 1. Check the vote meets the ballot requirements
    component ballotModeChecker = CheckBallotMode(n_fields);
    ballotModeChecker.fields <== fields;
    ballotModeChecker.num_fields <== num_fields;
    ballotModeChecker.group_size <== group_size;
    ballotModeChecker.unique_values <== unique_values;
    ballotModeChecker.max_value <== max_value;
    ballotModeChecker.min_value <== min_value;
    ballotModeChecker.max_value_sum <== max_value_sum;
    ballotModeChecker.min_value_sum <== min_value_sum;
    ballotModeChecker.cost_exponent <== cost_exponent;
    ballotModeChecker.weight <== weight;

    // 2. Check the encrypted vote
    component ballotCipher = BallotCipher(n_fields);
    ballotCipher.encryption_pubkey <== encryption_pubkey;
    ballotCipher.k <== k;
    ballotCipher.fields <== fields;
    ballotCipher.mask <== ballotModeChecker.mask;
    ballotCipher.cipherfields <== cipherfields;
    ballotCipher.valid_fields === num_fields;

    // 3. Check the vote ID
    component voteIDChecker = VoteIDChecker();
    voteIDChecker.process_id <== process_id;
    voteIDChecker.address <== address;
    voteIDChecker.k <== k;
    voteIDChecker.vote_id <== vote_id;
}

component main {public [address, vote_id, process_id, packed_ballot_mode, encryption_pubkey, weight, cipherfields]} = BallotProof(16);
