import { buildElGamal, ElGamal } from './elgamal.js';
import { buildPoseidon } from '@vocdoni/poseidon377js';
import { Point } from './curve.js';

export interface BallotConfig {
    numFields: number;
    uniqueValues: number;
    maxValue: number;
    minValue: number;
    maxValueSum: number;
    minValueSum: number;
    costExponent: number;
    costFromWeight: number;
}

export interface BallotInputs {
    fields: number[];
    weight: number;
    encryption_pubkey: string[];
    cipherfields: string[][][];
    process_id: string;
    address: string;
    k: string;
    vote_id: string;
    inputs_hash: string;
    // Config
    num_fields: number;
    unique_values: number;
    max_value: number;
    min_value: number;
    max_value_sum: number;
    min_value_sum: number;
    cost_exponent: number;
    cost_from_weight: number;
}

export class BallotBuilder {
    elgamal: ElGamal;
    poseidon: any;

    constructor(elgamal: ElGamal, poseidon: any) {
        this.elgamal = elgamal;
        this.poseidon = poseidon;
    }

    static async build(singleThread: boolean = false): Promise<BallotBuilder> {
        const elgamal = await buildElGamal(singleThread);
        const poseidon = await buildPoseidon(singleThread);
        return new BallotBuilder(elgamal, poseidon);
    }

    randomK(): string {
        return this.elgamal.randomScalar().toString();
    }

    derivePoseidonChain(seedK: string, n: number): string[] {
        let current = BigInt(seedK);
        const out: string[] = [current.toString()];
        for (let i = 0; i < n; i++) {
            // Hash(0, current)
            const h = this.poseidon.hash([current], 0);
            const hBig = BigInt(this.poseidon.F.toString(h, 10));
            out.push(hBig.toString());
            current = hBig;
        }
        return out;
    }

    encryptFields(fields: number[], pubKey: Point, seedK: string, nFields: number) {
        // Pad fields with 0 if necessary?
        // Circuit usually expects fixed array. nFields is config.
        const paddedFields = [...fields];
        while (paddedFields.length < nFields) {
            paddedFields.push(0);
        }

        const ks = this.derivePoseidonChain(seedK, nFields);
        const cipherfields: string[][][] = [];

        for (let i = 0; i < nFields; i++) {
            const k = ks[i + 1]; // Use derived k
            const msg = BigInt(paddedFields[i]);
            const enc = this.elgamal.encrypt(msg, pubKey, k);
            
            cipherfields.push([
                [this.elgamal.curve.F.toString(enc.c1.x, 10), this.elgamal.curve.F.toString(enc.c1.y, 10)],
                [this.elgamal.curve.F.toString(enc.c2.x, 10), this.elgamal.curve.F.toString(enc.c2.y, 10)]
            ]);
        }
        return { cipherfields, paddedFields };
    }

    computeVoteID(processId: string, address: string, k: string): string {
        const h = this.poseidon.hash([BigInt(processId), BigInt(address), BigInt(k)], 0);
        const hBig = BigInt(this.poseidon.F.toString(h, 10));
        const mask = (1n << 160n) - 1n;
        return (hBig & mask).toString();
    }

    computeInputsHash(inputs: any[]): string {
        // MultiHash(0, inputs...)
        const mh = this.poseidon.multiHash(inputs, 0);
        return this.poseidon.F.toString(mh, 10);
    }

    generateInputs(
        fields: number[],
        weight: number,
        pubKey: Point,
        processId: string,
        address: string,
        k: string,
        config: BallotConfig,
        circuitCapacity: number = 8
    ): BallotInputs {
        // activeFields is the actual number of choices provided
        const activeFields = fields.length;
        
        // Encrypt fields (padded to circuit capacity)
        const { cipherfields, paddedFields } = this.encryptFields(fields, pubKey, k, circuitCapacity);
        const voteId = this.computeVoteID(processId, address, k);

        // Build Inputs Hash
        const inputsList: any[] = [];
        for (const f of paddedFields) inputsList.push(BigInt(f));
        inputsList.push(BigInt(weight));
        inputsList.push(BigInt(this.poseidon.F.toString(pubKey.x, 10)));
        inputsList.push(BigInt(this.poseidon.F.toString(pubKey.y, 10)));
        for (const cf of cipherfields) {
            inputsList.push(BigInt(cf[0][0]));
            inputsList.push(BigInt(cf[0][1]));
            inputsList.push(BigInt(cf[1][0]));
            inputsList.push(BigInt(cf[1][1]));
        }
        inputsList.push(BigInt(processId));
        inputsList.push(BigInt(address));
        inputsList.push(BigInt(k));
        inputsList.push(BigInt(voteId));
        // Use activeFields for the signal
        inputsList.push(BigInt(activeFields));
        inputsList.push(BigInt(config.uniqueValues));
        inputsList.push(BigInt(config.maxValue));
        inputsList.push(BigInt(config.minValue));
        inputsList.push(BigInt(config.maxValueSum));
        inputsList.push(BigInt(config.minValueSum));
        inputsList.push(BigInt(config.costExponent));
        inputsList.push(BigInt(config.costFromWeight));

        const inputsHash = this.computeInputsHash(inputsList);

        return {
            fields: paddedFields,
            weight,
            encryption_pubkey: [
                this.poseidon.F.toString(pubKey.x, 10),
                this.poseidon.F.toString(pubKey.y, 10)
            ],
            cipherfields,
            process_id: processId,
            address,
            k,
            vote_id: voteId,
            inputs_hash: inputsHash,
            // Config
            num_fields: activeFields,
            unique_values: config.uniqueValues,
            max_value: config.maxValue,
            min_value: config.minValue,
            max_value_sum: config.maxValueSum,
            min_value_sum: config.minValueSum,
            cost_exponent: config.costExponent,
            cost_from_weight: config.costFromWeight,
        };
    }
}
