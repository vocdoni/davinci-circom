pragma circom 2.0.0;

include "poseidon377_constants.circom";

// SBox optimized: x^17 using 5 multiplications
template Poseidon377SBox() {
    signal input in;
    signal output out;

    signal m2 <== in * in;
    signal m4 <== m2 * m2;
    signal m8 <== m4 * m4;
    signal m16 <== m8 * m8;
    out <== m16 * in;
}

// Dense Matrix Multiplication
template Poseidon377Mix(t, rate) {
    signal input in[t];
    signal output out[t];
    
    var mds[8][8] = getPoseidon377MDS(rate); // Assuming max t=8
    
    for (var i = 0; i < t; i++) {
        var sum = 0;
        for (var j = 0; j < t; j++) {
            sum += mds[i][j] * in[j];
        }
        out[i] <== sum;
    }
}

// Mix using MI (for first partial round)
template Poseidon377MixMI(t, rate) {
    signal input in[t];
    signal output out[t];
    
    var mi[8][8] = getPoseidon377MI(rate);
    
    for (var i = 0; i < t; i++) {
        var sum = 0;
        for (var j = 0; j < t; j++) {
            sum += mi[i][j] * in[j];
        }
        out[i] <== sum;
    }
}

// Sparse Matrix Multiplication
// state[0] = M00 * state[0] + sum(WHat[i] * state[i+1])
// state[i+1] = V[i] * state[0] + state[i+1]
template Poseidon377SparseMix(t, rate, round) {
    signal input in[t];
    signal output out[t];
    
    // Get constants
    // Arrays are flat. Offset: round * (t-1).
    var v[400] = getPoseidon377SparseV(rate);
    var w[400] = getPoseidon377SparseWHat(rate);
    var m00 = getPoseidon377M00(rate);
    
    var subSize = t - 1;
    var offset = round * subSize;
    
    // Compute new state[0]
    var sum0 = m00 * in[0];
    for (var i = 0; i < subSize; i++) {
        sum0 += w[offset + i] * in[i+1];
    }
    out[0] <== sum0;
    
    // Compute new state[i+1]
    for (var i = 0; i < subSize; i++) {
        out[i+1] <== v[offset + i] * in[0] + in[i+1];
    }
}

template Poseidon377Permutation(rate) {
    var t = rate + 1;
    signal input in[t];
    signal output out[t];
    
    var rounds[2] = getPoseidon377Rounds(rate);
    var RF = rounds[0];
    var RP = rounds[1];
    var rF_half = RF / 2;
    
    var arc[520] = getPoseidon377ARC(rate);
    
    signal state[RF + RP + 2][t]; // State after each round + initial
    state[0] <== in;
    
    // First half full rounds
    component fullSBox1[rF_half][t];
    component fullMix1[rF_half];
    
    for (var r = 0; r < rF_half; r++) {
        // Add Round Constants
        var arcOffset = r * t;
        for (var i = 0; i < t; i++) {
            fullSBox1[r][i] = Poseidon377SBox();
            fullSBox1[r][i].in <== state[r][i] + arc[arcOffset + i];
        }
        
        // Mix
        fullMix1[r] = Poseidon377Mix(t, rate);
        for (var i = 0; i < t; i++) {
            fullMix1[r].in[i] <== fullSBox1[r][i].out;
        }
        state[r+1] <== fullMix1[r].out;
    }
    
    var currentRound = rF_half;
    
    // First Partial Round (Dense Mix MI)
    
    // Round rF (First partial logic)
    // state[rF_half] is output of last full round.
    // We add ARC[rF_half * t] then MixMI.
    
    var roundIdx = rF_half;
    
    signal afterArc[t];
    var arcOffset = roundIdx * t;
    for(var i=0; i<t; i++) {
        afterArc[i] <== state[roundIdx][i] + arc[arcOffset + i];
    }
    
    component compMixMI = Poseidon377MixMI(t, rate);
    compMixMI.in <== afterArc;
    state[roundIdx+1] <== compMixMI.out;
    
    // Middle Partial Rounds (RP - 1 rounds)
    
    component middleSBox[RP-1];
    component middleMix[RP-1];
    signal sboxOut[RP-1];
    
    for (var r = 0; r < RP - 1; r++) {
        var stateIdx = roundIdx + 1 + r;
        
        // SBox on state[0]
        middleSBox[r] = Poseidon377SBox();
        middleSBox[r].in <== state[stateIdx][0]; // SBox applied directly to state
        
        // Add Constant to SBox output (only to 0-th element)
        var constIdx = rF_half + 1 + r;
        var arcVal = arc[constIdx * t];
        
        sboxOut[r] <== middleSBox[r].out + arcVal;
        
        // Sparse Mix
        var sparseRound = RP - r - 1;
        
        middleMix[r] = Poseidon377SparseMix(t, rate, sparseRound);
        middleMix[r].in[0] <== sboxOut[r];
        for(var i=1; i<t; i++) {
            middleMix[r].in[i] <== state[stateIdx][i];
        }
        state[stateIdx+1] <== middleMix[r].out;
    }
    
    // Final Partial Round
    var finalPartialIdx = roundIdx + 1 + RP - 1;
    component finalPartialSBox = Poseidon377SBox();
    finalPartialSBox.in <== state[finalPartialIdx][0];
    
    component finalPartialMix = Poseidon377SparseMix(t, rate, 0); // round 0
    finalPartialMix.in[0] <== finalPartialSBox.out;
    for(var i=1; i<t; i++) {
        finalPartialMix.in[i] <== state[finalPartialIdx][i];
    }
    state[finalPartialIdx+1] <== finalPartialMix.out;
    
    // Second half Full Rounds
    var roundFull2 = rF_half + RP;
    
    component fullSBox2[rF_half][t];
    component fullMix2[rF_half];
    
    for (var r = 0; r < rF_half; r++) {
        var stateIdx = finalPartialIdx + 1 + r;
        var rConstIdx = roundFull2 + r;
        
        var arcOffset2 = rConstIdx * t;
        for (var i = 0; i < t; i++) {
            fullSBox2[r][i] = Poseidon377SBox();
            fullSBox2[r][i].in <== state[stateIdx][i] + arc[arcOffset2 + i];
        }
        
        fullMix2[r] = Poseidon377Mix(t, rate);
        for (var i = 0; i < t; i++) {
            fullMix2[r].in[i] <== fullSBox2[r][i].out;
        }
        state[stateIdx+1] <== fullMix2[r].out;
    }
    
    out <== state[finalPartialIdx + 1 + rF_half];
}

// Helper to hash a chunk using a specific rate
template Poseidon377Chunk(rate) {
    signal input domain;
    signal input in[rate];
    signal output out;
    
    component perm = Poseidon377Permutation(rate);
    perm.in[0] <== domain;
    for (var i = 0; i < rate; i++) {
        perm.in[i+1] <== in[i];
    }
    out <== perm.out[1]; // Sponge output is state[1]
}

// MultiHash for N inputs
// Optimized for rate 7 chunks.
// Supports N up to 256.
// Tree structure:
// Level 0: chunks of 7 inputs. Hash(domain, chunk).
// Level 1: chunks of 7 hashes from level 0. Hash(domain, chunk).
// ...
template Poseidon377MultiHash(n) {
    signal input in[n]; // Domain is implicitly used inside (could be input, but fixed usually)
    signal input domain;
    signal output out;
    
    var maxRate = 7;
    
    // Level 0
    var n0 = n;
    var numChunks0 = (n0 + maxRate - 1) \ maxRate;
    signal level0_out[numChunks0];
    
    component hashers0[numChunks0];
    
    for (var i = 0; i < numChunks0; i++) {
        var start = i * maxRate;
        var end = start + maxRate;
        if (end > n0) end = n0;
        var currentRate = end - start;
        
        hashers0[i] = Poseidon377Chunk(currentRate);
        hashers0[i].domain <== domain;
        for (var j = 0; j < currentRate; j++) {
            hashers0[i].in[j] <== in[start + j];
        }
        level0_out[i] <== hashers0[i].out;
    }
    
    // Level 1
    if (numChunks0 > 1) {
        var n1 = numChunks0;
        var numChunks1 = (n1 + maxRate - 1) \ maxRate;
        signal level1_out[numChunks1];
        component hashers1[numChunks1];
        
        for (var i = 0; i < numChunks1; i++) {
            var start = i * maxRate;
            var end = start + maxRate;
            if (end > n1) end = n1;
            var currentRate = end - start;
            
            hashers1[i] = Poseidon377Chunk(currentRate);
            hashers1[i].domain <== domain;
            for (var j = 0; j < currentRate; j++) {
                hashers1[i].in[j] <== level0_out[start + j];
            }
            level1_out[i] <== hashers1[i].out;
        }
        
        // Level 2
        if (numChunks1 > 1) {
            var n2 = numChunks1;
            var numChunks2 = (n2 + maxRate - 1) \ maxRate;
            signal level2_out[numChunks2];
            component hashers2[numChunks2];
            
            for (var i = 0; i < numChunks2; i++) {
                var start = i * maxRate;
                var end = start + maxRate;
                if (end > n2) end = n2;
                var currentRate = end - start;
                
                hashers2[i] = Poseidon377Chunk(currentRate);
                hashers2[i].domain <== domain;
                for (var j = 0; j < currentRate; j++) {
                    hashers2[i].in[j] <== level1_out[start + j];
                }
                level2_out[i] <== hashers2[i].out;
            }
            
            if (numChunks2 > 1) {
                out <== level2_out[0]; // Assuming max depth is reached.
            } else {
                out <== level2_out[0];
            }
        } else {
            out <== level1_out[0];
        }
    } else {
        out <== level0_out[0];
    }
}