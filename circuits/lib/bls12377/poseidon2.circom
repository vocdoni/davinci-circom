pragma circom 2.0.0;

include "poseidon2_constants.circom";

// SBox optimized: x^17 using 5 multiplications
template Poseidon2SBox() {
    signal input in;
    signal output out;

    signal m2 <== in * in;
    signal m4 <== m2 * m2;
    signal m8 <== m4 * m4;
    signal m16 <== m8 * m8;
    out <== m16 * in;
}

// matMulExternal for t=2: circ(2, 1)
template Poseidon2MatMulExternal2() {
    signal input in[2];
    signal output out[2];

    signal tmp <== in[0] + in[1];
    out[0] <== in[0] + tmp;
    out[1] <== in[1] + tmp;
}

// matMulInternal for t=2: [[2, 1], [1, 3]]
template Poseidon2MatMulInternal2() {
    signal input in[2];
    signal output out[2];

    signal sum <== in[0] + in[1];
    out[0] <== in[0] + sum;
    out[1] <== 2 * in[1] + sum;
}

template Poseidon2Permutation2() {
    signal input in[2];
    signal output out[2];

    var RF = 6;
    var RP = 26;
    var roundKeys[32][2] = getPoseidon2RoundKeys();

    component initialMix = Poseidon2MatMulExternal2();
    initialMix.in <== in;

    signal state[33][2];
    state[0] <== initialMix.out;

    component fullSBox1[3][2];
    component fullMix1[3];
    
    // First 3 Full Rounds
    for (var i = 0; i < 3; i++) {
        fullSBox1[i][0] = Poseidon2SBox();
        fullSBox1[i][1] = Poseidon2SBox();
        fullSBox1[i][0].in <== state[i][0] + roundKeys[i][0];
        fullSBox1[i][1].in <== state[i][1] + roundKeys[i][1];
        
        fullMix1[i] = Poseidon2MatMulExternal2();
        fullMix1[i].in[0] <== fullSBox1[i][0].out;
        fullMix1[i].in[1] <== fullSBox1[i][1].out;
        state[i+1] <== fullMix1[i].out;
    }

    // 26 Partial Rounds
    component partialSBox[26];
    component partialMix[26];
    for (var i = 0; i < 26; i++) {
        partialSBox[i] = Poseidon2SBox();
        partialSBox[i].in <== state[i+3][0] + roundKeys[i+3][0];
        
        partialMix[i] = Poseidon2MatMulInternal2();
        partialMix[i].in[0] <== partialSBox[i].out;
        partialMix[i].in[1] <== state[i+3][1]; // No round key for partial round index 1
        state[i+4] <== partialMix[i].out;
    }

    // Last 3 Full Rounds
    component fullSBox2[3][2];
    component fullMix2[3];
    for (var i = 0; i < 3; i++) {
        fullSBox2[i][0] = Poseidon2SBox();
        fullSBox2[i][1] = Poseidon2SBox();
        fullSBox2[i][0].in <== state[i+29][0] + roundKeys[i+29][0];
        fullSBox2[i][1].in <== state[i+29][1] + roundKeys[i+29][1];
        
        fullMix2[i] = Poseidon2MatMulExternal2();
        fullMix2[i].in[0] <== fullSBox2[i][0].out;
        fullMix2[i].in[1] <== fullSBox2[i][1].out;
        state[i+30] <== fullMix2[i].out;
    }

    out <== state[32];
}

// Merkle-Damgard Hash using Poseidon2 Permutation (t=2)
template Poseidon2Hash(n) {
    signal input in[n];
    signal output out;

    if (n == 0) {
        out <== 0;
    } else {
        signal state[n+1];
        state[0] <== 0; // IV

        component comp[n];
        for (var i = 0; i < n; i++) {
            comp[i] = Poseidon2Permutation2();
            comp[i].in[0] <== state[i];
            comp[i].in[1] <== in[i];
            state[i+1] <== comp[i].out[1] + in[i]; // Miyaguchi-Preneel like feed-forward
        }
        out <== state[n];
    }
}
