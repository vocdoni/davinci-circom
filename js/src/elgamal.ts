// @ts-ignore
import { buildBls12377 } from 'ffjavascript';
import { Curve, Point } from './curve.js';

function getRandomBytes(n: number): Uint8Array {
    if (typeof globalThis.crypto !== 'undefined' && globalThis.crypto.getRandomValues) {
        return globalThis.crypto.getRandomValues(new Uint8Array(n));
    }
    throw new Error("Crypto not available");
}

export interface ElGamal {
    curve: Curve;
    encrypt: (msg: bigint | string, pubKey: Point, k: bigint | string) => { c1: Point, c2: Point };
    generateKeyPair: () => { privKey: bigint, pubKey: Point };
    randomScalar: () => bigint;
}

export async function buildElGamal(singleThread: boolean = false): Promise<ElGamal> {
    const bls = await buildBls12377(singleThread);
    const F = bls.Fr;
    const curve = new Curve(F);

    function randomScalar(): bigint {
        const bytes = getRandomBytes(32);
        let bi = 0n;
        for (let i = 0; i < bytes.length; i++) {
            bi += BigInt(bytes[i]) << BigInt(8 * i);
        }
        // Ensure it's in field
        return BigInt(F.toString(F.e(bi)));
    }

    function generateKeyPair() {
        const privKey = randomScalar();
        const pubKey = curve.Base.mul(privKey);
        return { privKey, pubKey };
    }

    function encrypt(msg: bigint | string, pubKey: Point, k: bigint | string) {
        const kVal = BigInt(k);
        const mVal = BigInt(msg);

        // c1 = k * G
        const c1 = curve.Base.mul(kVal);

        // s = k * Pub
        const s = pubKey.mul(kVal);

        // mPoint = m * G
        const mPoint = curve.Base.mul(mVal);

        // c2 = mPoint + s
        const c2 = mPoint.add(s);

        return { c1, c2 };
    }

    return {
        curve,
        encrypt,
        generateKeyPair,
        randomScalar
    };
}
