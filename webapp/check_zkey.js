import * as snarkjs from 'snarkjs';
import fs from 'fs';

async function check() {
    const fd = fs.openSync('public/ballot_proof_pkey.zkey', 'r');
    try {
        // snarkjs internal API is not always exposed clearly.
        // But let's try to verify protocol.
        // Actually, zkeyUtils is what we need.
        // snarkjs exports zKey?
        // console.log(snarkjs.zKey); 
        // snarkjs.zKey.readHeader(fd)
        
        // If not exposed, we can read raw bytes.
        // Header: "snarkjs", version, protocol, curveID?
        
        // Using snarkjs CLI is easier if installed.
        // npx snarkjs zkey export bellman public/ballot_proof_pkey.zkey /dev/null
        // It prints info.
    } catch (e) {
        console.error(e);
    }
}
// check();
