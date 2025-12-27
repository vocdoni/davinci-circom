pragma circom 2.0.0;

include "bitify.circom";

// BLS12-377 Twisted Edwards Curve
// -x^2 + y^2 = 1 + 3021 x^2 y^2

template PointAdd() {
    signal input x1;
    signal input y1;
    signal input x2;
    signal input y2;
    signal output xout;
    signal output yout;

    var a = -1;
    var d = 3021;

    signal beta <== x1*y2;
    signal gamma <== y1*x2;
    signal delta <== (-a*x1 + y1) * (x2 + y2);
    signal tau <== beta * gamma;
    
    signal dtau <== d * tau;

    xout <-- (beta + gamma) / (1 + dtau);
    (1 + dtau) * xout === beta + gamma;

    yout <-- (delta + a*beta - gamma) / (1 - dtau);
    (1 - dtau) * yout === delta + a*beta - gamma;
}

template PointDouble() {
    signal input x;
    signal input y;
    signal output xout;
    signal output yout;

    component adder = PointAdd();
    adder.x1 <== x;
    adder.y1 <== y;
    adder.x2 <== x;
    adder.y2 <== y;
    xout <== adder.xout;
    yout <== adder.yout;
}

template PointOnCurve() {
    signal input x;
    signal input y;
    signal x2 <== x*x;
    signal y2 <== y*y;
    var a = -1;
    var d = 3021;
    a*x2 + y2 === 1 + d*x2*y2;
}

// Functions for compile-time calculation
function VarPointAdd(x1, y1, x2, y2) {
    var a = -1;
    var d = 3021;
    var xout;
    var yout;
    
    var beta = x1 * y2;
    var gamma = y1 * x2;
    var tau = beta * gamma;
    var dtau = d * tau;
    
    xout = (beta + gamma) / (1 + dtau);
    yout = (y1*y2 - a*x1*x2) / (1 - dtau);
    
    return [xout, yout];
}

function VarPointDouble(x, y) {
    return VarPointAdd(x, y, x, y);
}