pragma circom 2.1.0;

include "circomlib/circuits/bitify.circom";
include "circomlib/circuits/comparators.circom";
include "./lib/math.circom";
include "./lib/utils.circom";

template MaskGeneratorBounded(n, n_bits) {
    signal input in;
    signal output out[n];

    component control = LessThan(n_bits);
    control.in[0] <== in;
    control.in[1] <== n + 1;
    assert(control.out == 1);

    component lt[n];
    for (var i = 0; i < n; i++) {
        lt[i] = LessThan(n_bits);
        lt[i].in[0] <== i;
        lt[i].in[1] <== in;
        out[i] <== lt[i].out;
    }
}

template ArrayInBoundsBounded(n, value_bits) {
    signal input arr[n];
    signal input mask[n];
    signal input min;
    signal input max;

    component bits[n];
    for (var i = 0; i < n; i++) {
        bits[i] = Num2Bits(value_bits);
        bits[i].in <== arr[i];
    }

    component lt[n];
    component gt[n];
    for (var i = 0; i < n; i++) {
        // enforce each element is in bounds
        lt[i] = GreaterThan(value_bits);
        lt[i].in[0] <== arr[i];
        lt[i].in[1] <== max;           // inclusive upper bound
        lt[i].out * mask[i] === 0;

        gt[i] = LessThan(value_bits);
        gt[i].in[0] <== arr[i];
        gt[i].in[1] <== min;           // inclusive lower bound
        gt[i].out * mask[i] === 0;
    }
}

template BallotChecker(n_fields) {
    signal input fields[n_fields];
    signal input num_fields;
    signal input group_size;
    signal input unique_values;
    signal input max_value;
    signal input min_value;
    signal input max_value_sum;
    signal input min_value_sum;
    signal input cost_exponent;
    signal input cost_from_weight;
    signal input weight;
    // return the mask of valid fields to be used in other components
    signal output mask[n_fields];
    component mask_gen = MaskGeneratorBounded(n_fields, 8);
    mask_gen.in <== num_fields;
    mask <== mask_gen.out;

    // group_size must be <= num_fields
    component groupWithin = LessEqThan(8);
    groupWithin.in[0] <== group_size;
    groupWithin.in[1] <== num_fields;
    groupWithin.out === 1;

    // all fields must be different
    component unique = UniqueArray(n_fields);
    unique.arr <== fields;
    unique.mask <== mask;
    unique.sel <== unique_values;

    // every field must be between min_value and max_value
    component inBounds = ArrayInBoundsBounded(n_fields, 48);
    inBounds.arr <== fields;
    inBounds.mask <== mask;
    inBounds.min <== min_value;
    inBounds.max <== max_value;

    // compute total cost: sum of all fields to the power of cost_exponent
    signal value_sum;
    component sum_calc = SumPow(n_fields, 8);
    sum_calc.inputs <== fields;
    sum_calc.mask <== mask;
    sum_calc.exp <== cost_exponent;
    value_sum <== sum_calc.out;

    // if max_value_sum is 0, it has not a max for the value sum
    component noMaxValueSum = IsZero();
    noMaxValueSum.in <== max_value_sum;

    // check if the max bound should be used:
    //  - if max_value_sum > 0 (noMaxValueSum == 1)
    //  - or cost_from_weight == 1
    component useMax = GreaterThan(128);
    useMax.in[0] <== noMaxValueSum.out + cost_from_weight;
    useMax.in[1] <== 0;


    // select max_value_sum if cost_from_weight is 0, otherwise use weight
    component finalMax = Mux();
    finalMax.a <== max_value_sum;
    finalMax.b <== weight;
    mux.sel <== cost_from_weight;

    // check bounds:
    //   min_value_sum <= value_sum <= (cost_from_weight or max_value_sum)

    //  value_sum <= (cost_from_weight or max_value_sum)
    component lt = LessEqThan(128);
    lt.in[0] <== value_sum;
    lt.in[1] <== mux.out;

    // only enforce max bound when max_value_sum > 0 or cost_from_weight == 1
    useMax.out * lt.out === useMax.out;

    // second: min_value_sum <= value_sum
    component gt = GreaterThan(128);
    // encrease by 1 the value_sum to allow equality with min_value_sum and 
    // avoid negative overflow decreasing min_value_sum
    gt.in[0] <== value_sum + 1;
    gt.in[1] <== min_value_sum; 
    gt.out === 1;
}

