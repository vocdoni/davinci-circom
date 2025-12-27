pragma circom 2.0.0;

include "twisted_edwards.circom";
include "montgomery.circom";
include "mux3.circom";

template EscalarMulFix(n, base) {
    signal input e[n];
    signal output out[2];

    var nSegments = (n + 2) \ 3; // Integer division ceil
    
    // Precompute table in Montgomery form
    
    var tableU[nSegments][8];
    var tableV[nSegments][8];
    
    var currentP[2];
    currentP[0] = base[0];
    currentP[1] = base[1];
    
    var tempP[2];
    var dblP[2];
    var montP[2];
    
    for (var i = 0; i < nSegments; i++) {
        // 0 * P => (0, 1) in Edwards -> u = (1+1)/(1-1) = Inf?
        // Montgomery form (0,0) is point of order 2. Inf is neutral.
        // Affine formulas don't handle Inf.
        // We must ensure we don't select 0?
        // But window value 0 means add 0.
        // If we use 0 in Mux, we get 0 output.
        // We need to handle this.
        // Standard trick: Shift the scalar?
        // Or ensure the first window is non-zero?
        // Or use a dummy point and subtract later?
        // "circomlib" uses `WindowMulFix` that computes `base + scalar*base`.
        // So `in` is 3 bits -> `0..7`.
        // It computes `base * (1 + val)`.
        // So it computes `1*base, 2*base, ..., 8*base`.
        // This avoids 0!
        // Then we subtract `base`? Or `\sum base * 2^...`.
        // `Result = \sum (w_i + 1) * 8^i * P - \sum 8^i * P`.
        // We can precompute `Offset = \sum 8^i * P`.
        // And subtract it at the end?
        // Subtracting is adding `-Offset`.
        // So we add `-Offset` as the initial value of accumulator?
        // Yes!
        
        // Let's implement this "Shifted Window" approach.
        // Table will store: `1*P, 2*P, ..., 8*P`.
        // Mux selects one of them (0..7).
        
        // 1 * P
        montP = VarEdwards2Montgomery(currentP[0], currentP[1]);
        tableU[i][0] = montP[0];
        tableV[i][0] = montP[1];
        
        // 2 * P
        dblP = VarPointDouble(currentP[0], currentP[1]);
        montP = VarEdwards2Montgomery(dblP[0], dblP[1]);
        tableU[i][1] = montP[0];
        tableV[i][1] = montP[1];
        
        // 3 * P
        tempP = VarPointAdd(dblP[0], dblP[1], currentP[0], currentP[1]);
        montP = VarEdwards2Montgomery(tempP[0], tempP[1]);
        tableU[i][2] = montP[0];
        tableV[i][2] = montP[1];
        
        // 4 * P
        tempP = VarPointDouble(dblP[0], dblP[1]);
        montP = VarEdwards2Montgomery(tempP[0], tempP[1]);
        tableU[i][3] = montP[0];
        tableV[i][3] = montP[1];
        
        // 5 * P
        var fourP[2];
        fourP[0] = tempP[0];
        fourP[1] = tempP[1];
        tempP = VarPointAdd(fourP[0], fourP[1], currentP[0], currentP[1]);
        montP = VarEdwards2Montgomery(tempP[0], tempP[1]);
        tableU[i][4] = montP[0];
        tableV[i][4] = montP[1];
        
        // 6 * P
        tempP = VarPointAdd(fourP[0], fourP[1], dblP[0], dblP[1]);
        montP = VarEdwards2Montgomery(tempP[0], tempP[1]);
        tableU[i][5] = montP[0];
        tableV[i][5] = montP[1];
        
        // 7 * P
        tempP = VarPointAdd(tempP[0], tempP[1], currentP[0], currentP[1]);
        montP = VarEdwards2Montgomery(tempP[0], tempP[1]);
        tableU[i][6] = montP[0];
        tableV[i][6] = montP[1];
        
        // 8 * P (for value 7 in 0-indexed mux corresponding to 111=7)
        // Wait, Mux input 000 should map to 1*P. 001 to 2*P?
        // No, bits `000` = value 0. We want `(0+1)*P = 1*P`.
        // bits `111` = value 7. We want `(7+1)*P = 8*P`.
        
        tempP = VarPointDouble(fourP[0], fourP[1]); // 8*P
        montP = VarEdwards2Montgomery(tempP[0], tempP[1]);
        tableU[i][7] = montP[0];
        tableV[i][7] = montP[1];
        
        // Prepare P for next segment: P = 8 * P (which is tempP now)
        if (i < nSegments - 1) {
            currentP[0] = tempP[0];
            currentP[1] = tempP[1];
        }
    }
    
    // Select points
    component mux[nSegments];
    for (var i = 0; i < nSegments; i++) {
        mux[i] = MultiMux3(2);
        
        var idx = i * 3;
        mux[i].s[0] <== e[idx];
        if (idx + 1 < n) {
            mux[i].s[1] <== e[idx+1];
        } else {
            mux[i].s[1] <== 0;
        }
        if (idx + 2 < n) {
            mux[i].s[2] <== e[idx+2];
        } else {
            mux[i].s[2] <== 0;
        }
        
        for (var j = 0; j < 8; j++) {
            mux[i].c[0][j] <== tableU[i][j];
            mux[i].c[1][j] <== tableV[i][j];
        }
    }
    
    // Calculate total Offset to subtract
    // Offset = \sum_{i=0}^{nSegments-1} 8^i * base
    // This is simply: 111...1 (base 8) * base?
    // \sum 8^i = (8^n - 1)/7.
    // Calculate this point in Var logic.
    
    var offsetP[2];
    offsetP[0] = base[0];
    offsetP[1] = base[1];
    
    var totalOffset[2];
    // Init with first term (i=0): 1 * base
    totalOffset[0] = base[0];
    totalOffset[1] = base[1];
    
    var termP[2];
    termP[0] = base[0];
    termP[1] = base[1];
    
    for (var i = 1; i < nSegments; i++) {
        // termP = 8 * termP_prev
        var d2[2] = VarPointDouble(termP[0], termP[1]);
        var d4[2] = VarPointDouble(d2[0], d2[1]);
        termP = VarPointDouble(d4[0], d4[1]); // 8*P
        
        // totalOffset = totalOffset + termP
        totalOffset = VarPointAdd(totalOffset[0], totalOffset[1], termP[0], termP[1]);
    }
    
    // Convert Offset to Montgomery and NEGATE it
    var offMont[2] = VarEdwards2Montgomery(totalOffset[0], totalOffset[1]);
    // Negate in Montgomery: (u, -v) ? No, Montgomery B v^2 = ...
    // If v -> -v, equation holds.
    // So negate v coordinate.
    // Wait, B*y^2 ... y is v.
    // Yes, (u, -v) is negation.
    
    // We want Acc = (-Offset) + Mux_0 + Mux_1 ...
    // Note: Montgomery addition of P + (-P) is dangerous (infinity).
    // But here we are adding "random" window points.
    // The sum \sum (w_i+1)8^i P is (scalar + \sum 8^i) P.
    // We subtract \sum 8^i P.
    // Result is scalar * P.
    // Unless scalar is 0? If scalar is 0, we get 0 (Inf).
    // Montgomery Affine can't represent Inf.
    // So if scalar can be 0, this fails.
    // ElGamal ephemeral key `k` is random in Subgroup order. It's almost never 0.
    // `msg` can be 0.
    // If msg is 0, c2 = s + 0*G = s.
    // But `0` in Affine Edwards is `(0,1)`.
    // My circuit outputs Edwards.
    // `Montgomery2Edwards` of Inf?
    // We cannot represent Inf in Affine Montgomery.
    // This is a limitation.
    // But `circomlib` `EscalarMulFix` does exactly this?
    // Let's check if `circomlib` supports 0 scalar.
    // Usually it assumes non-zero.
    // In ElGamal, `k` is non-zero.
    // `msg`? Message can be 0.
    // But we map message bits? `Num2Bits` gives bits.
    // If bits are all 0, we perform `0 * G`.
    // This will fail in Montgomery Affine.
    // How to handle `msg=0`?
    // We can add a "dummy" 1 to scalar?
    // Or assume message is non-zero (e.g. padded).
    // Or use Projective arithmetic (more constraints).
    // `BallotCipher` encodes `msg` (field element). 0 is a valid vote?
    // `fields` can be 0.
    // So we MUST support 0.
    //
    // Alternative: Use the "Shifted Window" but subtract `Offset` at the very end in Edwards form?
    // `Sum = \sum Mux_i` (Montgomery) -> Edwards -> `Sub(Sum, Offset)`.
    // `EdwardsAdd` handles inverses.
    // `Sub(P1, P2) = Add(P1, -P2)`.
    // `-P2` in Edwards is `(-x, y)`.
    // So we can accumulate in Montgomery (avoiding Inf if Sum != Offset).
    // Sum = `(scalar + offset_scalar) * P`.
    // If scalar=0, Sum = Offset_scalar * P = Offset.
    // Then we subtract Offset.
    // Result = 0 (Edwards (0,1)).
    // `EdwardsAdd` handles `P + (-P)`?
    // `tau = x1*y2 * y1*(-x1) = -x1^2 y1 y2`.
    // Denom: `1 + d*tau`.
    // `xout = ... / (1+d*tau)`.
    // If `P + (-P)` -> (0,1) + (0,-1)? No.
    // `P + (-P)` gives (0,1).
    // `BabyAdd` formulas are complete for Twisted Edwards (handles neutral, doubling, etc).
    // So converting back to Edwards and subtracting there is SAFE.
    //
    // Is `Sum` (Montgomery) safe?
    // Sum corresponds to `(scalar + offset) * P`.
    // As long as `scalar + offset != order`, we are fine.
    // Offset is fixed. Scalar is small (32 bits for msg, 253 for k).
    // Order is large.
    // So Sum is never Inf (Montgomery).
    // So Montgomery accumulation is safe!
    
    // Implementation:
    // 1. Acc = Mux[0].
    // 2. Loop i=1..n-1: Acc = MontgomeryAdd(Acc, Mux[i]).
    // 3. Convert Acc to Edwards.
    // 4. EdwardsAdd(Acc, -Offset).
    
    component adders[nSegments - 1];
    
    if (nSegments == 1) {
        // Just one window.
        // Convert Mux[0] to Edwards.
        // Subtract Offset (which is 1*Base for 1 window? No, Offset matches nSegments).
        // If nSegments=1, Offset=1*Base. Mux[0] selects `(val+1)Base`.
        // Result `val*Base`.
        // Safe.
        // Wait, converting back then subtracting?
        // We need `Montgomery2Edwards`.
    } 
    
    component mont2ed = Montgomery2Edwards();
    
    if (nSegments == 1) {
        mont2ed.in[0] <== mux[0].out[0];
        mont2ed.in[1] <== mux[0].out[1];
    } else {
        adders[0] = MontgomeryAdd();
        adders[0].in1[0] <== mux[0].out[0];
        adders[0].in1[1] <== mux[0].out[1];
        adders[0].in2[0] <== mux[1].out[0];
        adders[0].in2[1] <== mux[1].out[1];
        
        for (var i = 1; i < nSegments - 1; i++) {
            adders[i] = MontgomeryAdd();
            adders[i].in1[0] <== adders[i-1].out[0];
            adders[i].in1[1] <== adders[i-1].out[1];
            adders[i].in2[0] <== mux[i+1].out[0];
            adders[i].in2[1] <== mux[i+1].out[1];
        }
        mont2ed.in[0] <== adders[nSegments - 2].out[0];
        mont2ed.in[1] <== adders[nSegments - 2].out[1];
    }
    
    // Subtract Offset in Edwards
    // -Offset = (-x, y)
    component finalSub = PointAdd();
    finalSub.x1 <== mont2ed.out[0];
    finalSub.y1 <== mont2ed.out[1];
    finalSub.x2 <== -totalOffset[0]; // Negate x
    finalSub.y2 <== totalOffset[1];
    
    out[0] <== finalSub.xout;
    out[1] <== finalSub.yout;
}
