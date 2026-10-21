pragma circom 2.1.0;

include "circomlib/circuits/comparators.circom";

// MaskGenerator without the assert(): same signals, same constraints.
template MaskGeneratorWithoutAssert(n, n_bits) {
    signal input in;
    signal output out[n];

    component control = LessThan(n_bits);
    control.in[0] <== in;
    control.in[1] <== n + 1;

    component lt[n];
    for (var i = 0; i < n; i++) {
        lt[i] = LessThan(n_bits);
        lt[i].in[0] <== i;
        lt[i].in[1] <== in;
        out[i] <== lt[i].out;
    }
}

component main = MaskGeneratorWithoutAssert(16, 8);
