pragma circom 2.1.0;

include "circomlib/circuits/compconstant.circom";

// The comparator inside Num2Bits_strict's AliasCheck on its own: out = 1 when
// the 254 input bits, read as an integer, exceed p - 1. Its witness for the
// bits of an aliased value is transplanted into
// main.voteIDChecker.bits.aliasCheck.compConstant of the ballot circuit by
// soundness_num2bits_test.go, so the edited witness breaks only the
// AliasCheck constraint itself.
component main = CompConstant(-1);
