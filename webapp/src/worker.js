import { BallotBuilder } from '@vocdoni/davinci-circom';
import * as snarkjs from 'snarkjs';
import { Buffer } from 'buffer';
import process from 'process';

self.Buffer = Buffer;
self.process = process;

self.onmessage = async (e) => {
    const { type, args, wasm, zkey, singleThread } = e.data;

    if (type === 'generateProof') {
        try {
            postMessage({ type: 'log', msg: `Initializing Worker...` });
            
            const buildStart = performance.now();
            const builder = await BallotBuilder.build();
            postMessage({ type: 'log', msg: `BallotBuilder & BN254 initialized in ${(performance.now() - buildStart).toFixed(2)}ms` });

            const { fieldsArr, weight, processId, address, k, config } = args;

            postMessage({ type: 'log', msg: "Generating Keys & Computing Inputs..." });
            const computeStart = performance.now();

            // Generate Keys
            const { pubKey } = builder.elgamal.generateKeyPair();

            // Use provided K or generate
            let kVal = k;
            if (!kVal) {
                kVal = builder.randomK();
            }

            const inputs = builder.generateInputs(
                fieldsArr,
                weight,
                pubKey,
                processId,
                address,
                kVal,
                config
            );
            postMessage({ type: 'log', msg: `Inputs Computed in ${(performance.now() - computeStart).toFixed(2)}ms` });

            postMessage({ type: 'log', msg: "Starting Groth16 Proof Generation (this may take a while)..." });
            const proveStart = performance.now();
            
            // Pass Buffers directly to snarkjs
            // WASM needs to be Uint8Array usually for WebAssembly.instantiate
            const wasmUint8 = new Uint8Array(wasm);
            const zkeyUint8 = new Uint8Array(zkey);

            const { proof, publicSignals } = await snarkjs.groth16.fullProve(inputs, wasmUint8, zkeyUint8);
            
            postMessage({ type: 'log', msg: `Proof Generated successfully in ${(performance.now() - proveStart).toFixed(2)}ms`, style: 'success' });

            postMessage({ 
                type: 'result', 
                proof, 
                publicSignals,
                generatedK: kVal
            });

        } catch (err) {
            console.error(err);
            postMessage({ type: 'error', msg: err.message });
        }
    }
};
