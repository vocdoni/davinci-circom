pragma circom 2.1.0;

include "../circuits/ballot_proof.circom";

component main{public [inputs_hash]} = BallotProof(8);