pragma circom 2.1.0;

include "../circuits/lib/math.circom";

// SumPow as instantiated by CheckBallotMode(16): 16 inputs, 8-bit exponent.
component main = SumPow(16, 8);
