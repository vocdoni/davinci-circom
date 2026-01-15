pragma circom 2.1.0;

include "circomlib/circuits/poseidon.circom";
include "circomlib/circuits/bitify.circom";
include "ballot_checker.circom";
include "ballot_cipher.circom";
include "./lib/multiposeidon.circom";
include "./lib/vote_id.circom";

// BallotProof is the circuit to prove a valid vote.
// The vote is valid if it meets the Ballot Protocol requirements, but also if the
// encrypted vote provided matches with the raw vote encrypted in this circuit.
template BallotProof(n_fields) {
    // Ballot inputs
    signal input fields[n_fields];
    signal input num_fields;
    signal input unique_values;
    signal input max_value;
    signal input min_value;
    signal input max_value_sum;
    signal input min_value_sum;
    signal input cost_exponent;
    signal input cost_from_weight;
    signal input address;
    signal input weight;
    signal input process_id;
    signal input vote_id;
    // ElGamal inputs
    signal input encryption_pubkey[2];
    signal input k;
    signal input cipherfields[n_fields][2][2];
    // Inputs hash signal will include all the inputs that could be public
    signal input inputs_hash;

    // 0. Check the hash of the inputs (all pubprivate inputs)
    //  a. Ballot metadata:
    //      - num_fields
    //      - unique_values
    //      - max_value
    //      - min_value
    //      - max_value_sum
    //      - min_value_sum
    //      - cost_exponent
    //      - cost_from_weight
    //  b. ProcessID
    //  c. Address
    //  d. Weight
    //  e. Encryption Key
    //  f. Cipherfields
    //  g. VoteID

    // Order of inputs for hashing (matching standard/old implementation)
    // 1. ProcessID
    // 2. Metadata (8 fields)
    // 3. Encryption Key (2 fields)
    // 4. Address
    // 5. VoteID
    // 6. Cipherfields (n_fields * 4)
    // 7. Weight
    
    // Total inputs calculation:
    // 1 (process_id) + 8 (metadata) + 2 (key) + 1 (address) + 1 (vote_id) + 4*n_fields + 1 (weight)
    // = 14 + 4*n_fields

    var static_inputs = 14; 
    var cipherfields_inputs = 4 * n_fields;
    var n_inputs = cipherfields_inputs + static_inputs; 
    component inputs_hasher = MultiPoseidon(n_inputs);
    var i = 0;
    inputs_hasher.in[i] <== process_id; i++;
    inputs_hasher.in[i] <== num_fields; i++;
    inputs_hasher.in[i] <== unique_values; i++;
    inputs_hasher.in[i] <== max_value; i++;
    inputs_hasher.in[i] <== min_value; i++;
    inputs_hasher.in[i] <== max_value_sum; i++;
    inputs_hasher.in[i] <== min_value_sum; i++;
    inputs_hasher.in[i] <== cost_exponent; i++;
    inputs_hasher.in[i] <== cost_from_weight; i++;
    inputs_hasher.in[i] <== encryption_pubkey[0]; i++;
    inputs_hasher.in[i] <== encryption_pubkey[1]; i++;
    inputs_hasher.in[i] <== address; i++;
    inputs_hasher.in[i] <== vote_id; i++;
    for (var f = 0; f < n_fields; f++) {
        inputs_hasher.in[i] <== cipherfields[f][0][0]; i++;
        inputs_hasher.in[i] <== cipherfields[f][0][1]; i++;
        inputs_hasher.in[i] <== cipherfields[f][1][0]; i++;
        inputs_hasher.in[i] <== cipherfields[f][1][1]; i++;
    }
    inputs_hasher.in[i] <== weight; i++;
    
    inputs_hasher.out === inputs_hash;

    // 1. Check the vote meets the ballot requirements
    component ballotProtocol = BallotChecker(n_fields);
    ballotProtocol.fields <== fields;
    ballotProtocol.num_fields <== num_fields;
    ballotProtocol.unique_values <== unique_values;
    ballotProtocol.max_value <== max_value;
    ballotProtocol.min_value <== min_value;
    ballotProtocol.max_value_sum <== max_value_sum;
    ballotProtocol.min_value_sum <== min_value_sum;
    ballotProtocol.cost_exponent <== cost_exponent;
    ballotProtocol.cost_from_weight <== cost_from_weight;
    ballotProtocol.weight <== weight;

    // 2. Check the encrypted vote
    component ballotCipher = BallotCipher(n_fields);
    ballotCipher.encryption_pubkey <== encryption_pubkey;
    ballotCipher.k <== k;
    ballotCipher.fields <== fields;
    ballotCipher.mask <== ballotProtocol.mask;
    ballotCipher.cipherfields <== cipherfields;
    ballotCipher.valid_fields === num_fields;

    // 3. Check the vote ID
    component voteIDChecker = VoteIDChecker();
    voteIDChecker.process_id <== process_id;
    voteIDChecker.address <== address;
    voteIDChecker.k <== k;
    voteIDChecker.vote_id <== vote_id;
}

component main {public [inputs_hash, address, vote_id]} = BallotProof(8);