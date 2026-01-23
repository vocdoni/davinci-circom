pragma circom 2.1.0;

include "circomlib/circuits/bitify.circom";
include "circomlib/circuits/poseidon.circom";

// VoteIDChecker is a circuit to check the validity of a vote ID. A valid vote
// ID is the Poseidon hash of the process ID, the address and the secret k of
// the voter, truncated to 63 bits (mod 2^63) and shifted by VoteIDMin.
template VoteIDChecker() {
    var VOTE_ID_MIN = 0x8000000000000000;  // a.k.a. VoteIDMin (0x8000_0000_0000_0000)

    signal input process_id;  // public
    signal input address;     // public
    signal input k;           // private
    signal input vote_id;    // public
    // calculate the vote ID using Poseidon hash
    component hasher = Poseidon(3);
    hasher.inputs[0] <== process_id;
    hasher.inputs[1] <== address;
    hasher.inputs[2] <== k;
    // bit decomposition of the hash output
    component bits = Num2Bits(254);
    bits.in <== hasher.out;
    // reconstruct the lowest 63 bits as the truncated hash
    signal res[64];
    res[0] <== 0;  // accumulator starts at 0
    for (var i = 0; i < 63; i++) {
        res[i+1] <== res[i] + (bits.out[i] * (1 << i));
    }
    // ensure that the output is the expected vote ID
    signal vote_id_expected;
    vote_id_expected <== res[63] + VOTE_ID_MIN;
    vote_id_expected === vote_id;
}
