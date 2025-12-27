pragma circom 2.0.0;

// Montgomery Curve: B*y^2 = x^3 + A*x^2 + x
// A = 29953
// B = 2793861572658336796379963558836028591854430633649789757755913142839050691746

template MontgomeryAdd() {
    signal input in1[2];
    signal input in2[2];
    signal output out[2];

    var A = 29953;
    var B = 2793861572658336796379963558836028591854430633649789757755913142839050691746;

    signal lam;
    
    // lambda = (y2 - y1) / (x2 - x1)
    lam <-- (in2[1] - in1[1]) / (in2[0] - in1[0]);
    lam * (in2[0] - in1[0]) === (in2[1] - in1[1]);

    signal lam2 <== lam * lam;
    signal Blam2 <== B * lam2;

    // x3 = B*lambda^2 - A - x1 - x2
    out[0] <== Blam2 - A - in1[0] - in2[0];
    
    // y3 = lambda*(x1 - x3) - y1
    out[1] <== lam * (in1[0] - out[0]) - in1[1];
}

template MontgomeryDouble() {
    signal input in[2];
    signal output out[2];

    var A = 29953;
    var B = 2793861572658336796379963558836028591854430633649789757755913142839050691746;

    signal x2 <== in[0] * in[0];
    signal lam;
    
    // lambda = (3*x1^2 + 2*A*x1 + 1) / (2*B*y1)
    signal num <== 3*x2 + 2*A*in[0] + 1;
    signal den <== 2*B*in[1];
    
    lam <-- num / den;
    lam * den === num;

    signal lam2 <== lam * lam;
    signal Blam2 <== B * lam2;

    // x3 = B*lambda^2 - A - 2*x1
    out[0] <== Blam2 - A - 2*in[0];
    
    // y3 = lambda*(x1 - x3) - y1
    out[1] <== lam * (in[0] - out[0]) - in[1];
}

template Edwards2Montgomery() {
    signal input in[2];
    signal output out[2];

    // u = (1+y)/(1-y)
    // v = u/x
    
    signal onePlusY <== 1 + in[1];
    signal oneMinusY <== 1 - in[1];
    
    out[0] <-- onePlusY / oneMinusY;
    out[0] * oneMinusY === onePlusY;
    
    out[1] <-- out[0] / in[0];
    out[1] * in[0] === out[0];
}

template Montgomery2Edwards() {
    signal input in[2];
    signal output out[2];

    // y = (u-1)/(u+1)
    // x = u/v
    
    signal uMinus1 <== in[0] - 1;
    signal uPlus1 <== in[0] + 1;
    
    out[1] <-- uMinus1 / uPlus1;
    out[1] * uPlus1 === uMinus1;
    
    out[0] <-- in[0] / in[1];
    out[0] * in[1] === in[0];
}

function VarEdwards2Montgomery(x, y) {
    // u = (1+y)/(1-y)
    // v = u/x
    var u = (1 + y) / (1 - y);
    var v = u / x;
    return [u, v];
}