pragma circom 2.1.0;

include "circomlib/circuits/bitify.circom";
include "circomlib/circuits/babyjub.circom";
include "circomlib/circuits/escalarmulany.circom";
include "circomlib/circuits/escalarmulfix.circom";

// ElGamal from circuits/lib/elgamal.circom with the 254 bits of k taken as
// inputs instead of being derived by Num2Bits(254). The component and signal
// names (messageBits, messagePoint, c1Point, sPoint, c2Point, c1, c2) match
// ElGamal's, so a witness of this circuit can be transplanted into
// main.ballotCipher.ciphers[i] of the ballot circuit by name. Used by
// soundness_num2bits_test.go to build the second (k + p) decomposition.
template ElGamalBits(msg_bits) {
    signal input encryption_pubkey[2];
    signal input msg;
    signal input kbits[254];
    signal output c1[2];
    signal output c2[2];

    var base[2] = [
        5299619240641551281634865583518297030282874472190772894086521144482721001553,
        16950150798460657717958625567821834550301663161624707787222815936182638968203
    ];

    component messageBits = Num2Bits(msg_bits);
    messageBits.in <== msg;
    component messagePoint = EscalarMulFix(msg_bits, base);
    for (var i = 0; i < msg_bits; i++) {
        messageBits.out[i] ==> messagePoint.e[i];
    }
    component c1Point = EscalarMulFix(254, base);
    for (var i = 0; i < 254; i++) {
        kbits[i] ==> c1Point.e[i];
    }
    component sPoint = EscalarMulAny(254);
    sPoint.p[0] <== encryption_pubkey[0];
    sPoint.p[1] <== encryption_pubkey[1];
    for (var i = 0; i < 254; i++) {
        kbits[i] ==> sPoint.e[i];
    }
    component c2Point = BabyAdd();
    c2Point.x1 <== messagePoint.out[0];
    c2Point.y1 <== messagePoint.out[1];
    c2Point.x2 <== sPoint.out[0];
    c2Point.y2 <== sPoint.out[1];
    c1[0] <== c1Point.out[0];
    c1[1] <== c1Point.out[1];
    c2[0] <== c2Point.xout;
    c2[1] <== c2Point.yout;
}

component main = ElGamalBits(48);
