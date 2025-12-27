pragma circom 2.0.0;

include "twisted_edwards.circom";
include "montgomery.circom";

template Multiplexor2() {
    signal input sel;
    signal input in[2][2];
    signal output out[2];

    out[0] <== (in[1][0] - in[0][0])*sel + in[0][0];
    out[1] <== (in[1][1] - in[0][1])*sel + in[0][1];
}

template EscalarMulAny(n) {
    signal input e[n];
    signal input p[2];
    signal output out[2];

    // Convert P to Montgomery
    component p2m = Edwards2Montgomery();
    p2m.in[0] <== p[0];
    p2m.in[1] <== p[1];
    
    signal montP[2];
    montP[0] <== p2m.out[0];
    montP[1] <== p2m.out[1];

    // Doubling chain: D[i] = 2^i * P
    component doublers[n];
    // Accumulation chain
    component adders[n];
    component muxes[n];
    
    // Initial Acc = P (corresponding to k_prefix=0 => result (0+1)P)
    signal acc[n+1][2];
    acc[0][0] <== montP[0];
    acc[0][1] <== montP[1];
    
    // D[0] = P
    signal d[n+1][2];
    d[0][0] <== montP[0];
    d[0][1] <== montP[1];

    for (var i = 0; i < n; i++) {
        // Calculate P + 2^i * P
        adders[i] = MontgomeryAdd();
        adders[i].in1[0] <== acc[i][0];
        adders[i].in1[1] <== acc[i][1];
        adders[i].in2[0] <== d[i][0];
        adders[i].in2[1] <== d[i][1];
        
        // Select new Acc
        muxes[i] = Multiplexor2();
        muxes[i].sel <== e[i];
        muxes[i].in[0][0] <== acc[i][0];
        muxes[i].in[0][1] <== acc[i][1];
        muxes[i].in[1][0] <== adders[i].out[0];
        muxes[i].in[1][1] <== adders[i].out[1];
        
        acc[i+1][0] <== muxes[i].out[0];
        acc[i+1][1] <== muxes[i].out[1];
        
        // Prepare next D
        if (i < n - 1) {
            doublers[i] = MontgomeryDouble();
            doublers[i].in[0] <== d[i][0];
            doublers[i].in[1] <== d[i][1];
            d[i+1][0] <== doublers[i].out[0];
            d[i+1][1] <== doublers[i].out[1];
        }
    }
    
    // Convert Acc back to Edwards
    component m2e = Montgomery2Edwards();
    m2e.in[0] <== acc[n][0];
    m2e.in[1] <== acc[n][1];
    
    // Subtract P (because we started with P)
    // res = Acc - P = Acc + (-P)
    // -P = (-x, y)
    component sub = PointAdd();
    sub.x1 <== m2e.out[0];
    sub.y1 <== m2e.out[1];
    sub.x2 <== -p[0];
    sub.y2 <== p[1];
    
    out[0] <== sub.xout;
    out[1] <== sub.yout;
}
