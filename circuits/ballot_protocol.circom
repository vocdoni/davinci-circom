pragma circom 2.1.0;

include "circomlib/circuits/bitify.circom";
include "circomlib/circuits/comparators.circom";

include "./lib/math.circom";
include "./lib/utils.circom";

function PackedBallotModeBits() { return 248; }
function NumFieldsBits() { return 8; }
function GroupSizeBits() { return 8; }
function UniqueValuesBits() { return 1; }
function CostExponentBits() { return 8; }
function MaxValueBits() { return 48; }
function MinValueBits() { return 48; }
function MaxValueSumBits() { return 63; }
function MinValueSumBits() { return 63; }

// UnpackBallotMode template receives a single signal with the packed Ballot 
// Mode in 248 bits. It returns the following decoded signals:
//   - NumFields: 8 bits - max 255
//   - GroupSize: 8 bits - max 255
//   - UniqueValues: 1 bit (true or false)
//   - CostExponent: 8 bits - max 255
//   - MaxValue: 48 bits - max 281474976710655
//   - MinValue: 48 bits - max 281474976710655
//   - MaxValueSum: 63 bits - max 9223372036854775807
//   - MinValueSum: 63 bits - max 9223372036854775807
template UnpackBallotMode() {
    signal input packed;
    signal output num_fields;
    signal output group_size;
    signal output unique_values;
    signal output cost_exponent;
    signal output max_value;
    signal output min_value;
    signal output max_value_sum;
    signal output min_value_sum;

    component bits = Num2Bits(PackedBallotModeBits());
    bits.in <== packed;

    // create a pad counter to read the correct bits for each decoded field
    var pad = 0;

    // get the value for the numFields number of bits
    component numFields = Bits2Num(NumFieldsBits());
    for (var i = 0; i < NumFieldsBits(); i++) {
        numFields.in[i] <== bits.out[pad + i];
    }
    num_fields <== numFields.out;
    // move the pad counter to the first bit after numFields
    pad += NumFieldsBits();
    
    // get the value for the groupSize number of bits
    component groupSize = Bits2Num(GroupSizeBits());
    for (var i = 0; i < GroupSizeBits(); i++) {
        groupSize.in[i] <== bits.out[pad + i];
    }
    group_size <== groupSize.out;
    // move the pad counter to the first bit after groupSize
    pad += GroupSizeBits();
    
    // get the value for the uniqueValues bit
    unique_values <== bits.out[pad];
    // move the pad counter to the first bit after uniqueValues
    pad += UniqueValuesBits();

    component costExp = Bits2Num(CostExponentBits());
    for (var i = 0; i < CostExponentBits(); i++) {
        costExp.in[i] <== bits.out[pad + i];
    }
    cost_exponent <== costExp.out;
    // move the pad counter to the first bit after costExponent
    pad += CostExponentBits();

    // get the value for the maxValue number of bits
    component maxValue = Bits2Num(MaxValueBits());
    for (var i = 0; i < MaxValueBits(); i++) {
        maxValue.in[i] <== bits.out[pad + i];
    }
    max_value <== maxValue.out;
    // move the pad counter to the first bit after maxValue
    pad += MaxValueBits();

    // get the value for the minValue number of bits
    component minValue = Bits2Num(MinValueBits());
    for (var i = 0; i < MinValueBits(); i++) {
        minValue.in[i] <== bits.out[pad + i];
    }
    min_value <== minValue.out;
    // move the pad counter to the first bit after minValue
    pad += MinValueBits();

    // get the value for the maxValueSum number of bits
    component maxValueSum = Bits2Num(MaxValueSumBits());
    for (var i = 0; i < MaxValueSumBits(); i++) {
        maxValueSum.in[i] <== bits.out[pad + i];
    }
    max_value_sum <== maxValueSum.out;
    // move the pad counter to the first bit after maxValueSum
    pad += MaxValueSumBits();

    // get the value for the minValueSum number of bits
    component minValueSum = Bits2Num(MinValueSumBits());
    for (var i = 0; i < MinValueSumBits(); i++) {
        minValueSum.in[i] <== bits.out[pad + i];
    }
    min_value_sum <== minValueSum.out;
}

// CheckBallotMode template ensures that the given ballot mode signals are 
// valid for the fields and weight signals provided:
//   - Ensures that the group size is lower or equal than the num of fields.
//   - If unique values flag is enabled, ensures that no field value is 
//     repeated.
//   - Ensures that each field value is in the [min value, max value] range.
//   - Ensures that the sum of fields values is in the [min value sum, max 
//     value sum] range. If the max value sum is zero, the upper bound will be
//     the weight.
template CheckBallotMode(n_fields) {
    signal input fields[n_fields];
    signal input num_fields;
    signal input group_size;
    signal input unique_values;
    signal input max_value;
    signal input min_value;
    signal input max_value_sum;
    signal input min_value_sum;
    signal input cost_exponent;
    signal input weight;
    // return the mask of valid fields
    signal output mask[n_fields];

    // calculate the mask of the fields to be used by other components
    component mask_gen = MaskGenerator(n_fields, NumFieldsBits());
    mask_gen.in <== num_fields;
    mask <== mask_gen.out;

    // group_size must be <= num_fields
    component groupWithin = LessEqThan(GroupSizeBits());
    groupWithin.in[0] <== group_size;
    groupWithin.in[1] <== num_fields;
    groupWithin.out === 1;

    // all fields must be different or not based on unique_values
    component checkUniqueValues = UniqueArray(n_fields);
    checkUniqueValues.arr <== fields;
    checkUniqueValues.mask <== mask;
    checkUniqueValues.sel <== unique_values;

    // every field must be between min_value and max_value
    component fieldsInBounds = ArrayInBounds(n_fields, MaxValueBits());
    fieldsInBounds.arr <== fields;
    fieldsInBounds.mask <== mask;
    fieldsInBounds.min <== min_value;
    fieldsInBounds.max <== max_value;

    // compute value sum: sum of all fields to the power of cost_exponent
    signal value_sum;
    component sum_calc = SumPow(n_fields, CostExponentBits());
    sum_calc.inputs <== fields;
    sum_calc.mask <== mask;
    sum_calc.exp <== cost_exponent;
    value_sum <== sum_calc.out;

    // if max_value_sum is 0, it has not a max for the value sum
    component noMaxValueSum = IsZero();
    noMaxValueSum.in <== max_value_sum;
    signal maxValueFromWeight;
    maxValueFromWeight <== noMaxValueSum.out;

    // finalMax will be max_value_sum if it is greater than 0, else it will be
    // the weight
    component finalMax = Mux();
    finalMax.a <== max_value_sum;
    finalMax.b <== weight;
    finalMax.sel <== maxValueFromWeight;

    // check upper bound: value_sum <= (max_value_sum or weight)
    component validValueForMax = LessEqThan(MaxValueSumBits());
    validValueForMax.in[0] <== value_sum;
    validValueForMax.in[1] <== finalMax.out;
    validValueForMax.out === 1;

    // check lower bound: min_value_sum <= value_sum
    component validValueForMin = LessEqThan(MinValueSumBits());
    validValueForMin.in[0] <== min_value_sum;
    validValueForMin.in[1] <== value_sum; 
    validValueForMin.out === 1;
}