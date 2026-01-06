import { expect } from "chai";
import { buildElGamal } from "../src/elgamal.js";
import { buildPoseidon } from "@vocdoni/poseidon377js";
import { Point } from "../src/curve.js";
import { BallotBuilder } from "../src/builder.js";

describe("Integration: Poseidon + ElGamal", function () {
    let elgamal: any;
    let poseidon: any;

    before(async () => {
        elgamal = await buildElGamal();
        poseidon = await buildPoseidon();
    });

    it("should match TestBallotCipher logic", async () => {
        const vector = {
            "c1": [
              "3275788839578713975392570611134636120538941737176167915581460336147861799793",
              "3834743499803638424335580201060497111758651857420118000031099206103628782976"
            ],
            "encryption_pubkey": [
              "6662335562523631072798944354192729060964292032791170381652625195267967090470",
              "1510120478366896408556192701290219358905597503325248662387933634561620998222"
            ],
            "k": "77133043288661348011445954248744555004576526375",
            "msg": "3"
        };

        // Derive k' = Hash(0, k)
        const kVal = BigInt(vector.k);
        const kDerived = poseidon.hash([kVal], 0); // Hash(domain=0, input=k)
        
        // Encrypt using kDerived
        const pubKey = new Point(
            elgamal.curve.F.e(vector.encryption_pubkey[0]),
            elgamal.curve.F.e(vector.encryption_pubkey[1]),
            elgamal.curve
        );

        // Convert kDerived (Fr Element) to BigInt for encryption
        const kDerivedStr = poseidon.F.toString(kDerived, 10);

        const result = elgamal.encrypt(vector.msg, pubKey, kDerivedStr);

        const c1x = elgamal.curve.F.toString(result.c1.x, 10);
        const c1y = elgamal.curve.F.toString(result.c1.y, 10);
        
        expect(c1x).to.equal(vector.c1[0], "c1.x mismatch");
        expect(c1y).to.equal(vector.c1[1], "c1.y mismatch");
    });

    it("should generate valid inputs for multiple fields (Rate 5)", async () => {
        const builder = await BallotBuilder.build();
        const config = {
            numFields: 8,
            uniqueValues: 1,
            maxValue: 16,
            minValue: 0,
            maxValueSum: 1125,
            minValueSum: 5,
            costExponent: 2,
            costFromWeight: 0
        };
        const fields = [1, 2, 3, 4, 5];
        const { pubKey } = builder.elgamal.generateKeyPair();
        const processId = "123";
        const address = "456";
        const k = builder.randomK();

        const inputs = builder.generateInputs(fields, 1, pubKey, processId, address, k, config);

        expect(inputs.fields).to.have.lengthOf(8);
        expect(inputs.fields.slice(0, 5)).to.deep.equal(fields);
        expect(inputs.fields.slice(5)).to.deep.equal([0, 0, 0]);
        expect(inputs.num_fields).to.equal(5);
        expect(inputs.cipherfields).to.have.lengthOf(8);
        expect(inputs.inputs_hash).to.be.a('string');
    });
});