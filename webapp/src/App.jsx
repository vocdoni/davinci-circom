import React, { useState, useEffect } from 'react';
import * as snarkjs from 'snarkjs';

function App() {
  const [logs, setLogs] = useState([]);
  const [proof, setProof] = useState(null);
  const [publicSignals, setPublicSignals] = useState(null);
  const [verificationResult, setVerificationResult] = useState(null);
  const [loading, setLoading] = useState(false);

  const addLog = (msg) => {
    const timestamp = new Date().toLocaleTimeString();
    setLogs((prev) => [`[${timestamp}] ${msg}`, ...prev]);
  };

  const generateProof = async () => {
    setLoading(true);
    addLog("Starting Proof Generation...");
    try {
      const startTime = performance.now();

      // Fetch input
      addLog("Fetching input.json...");
      const inputReq = await fetch('input.json');
      const input = await inputReq.json();
      addLog("Input fetched.");

      // Paths
      const wasmPath = 'ballot_proof.wasm';
      const zkeyPath = 'ballot_proof_pkey.zkey';

      addLog("Calling snarkjs.groth16.fullProve...");
      const { proof, publicSignals } = await snarkjs.groth16.fullProve(input, wasmPath, zkeyPath);
      
      const endTime = performance.now();
      const duration = (endTime - startTime).toFixed(2);
      
      addLog(`Proof Generated in ${duration}ms`);
      setProof(proof);
      setPublicSignals(publicSignals);
      setVerificationResult(null); // Reset verification
    } catch (err) {
      addLog(`Error: ${err.message}`);
      console.error(err);
    } finally {
      setLoading(false);
    }
  };

  const verifyProof = async () => {
    if (!proof || !publicSignals) {
      addLog("No proof to verify.");
      return;
    }
    setLoading(true);
    addLog("Starting Verification...");
    try {
      const startTime = performance.now();

      addLog("Fetching vkey...");
      const vkeyReq = await fetch('ballot_proof_vkey.json');
      const vkey = await vkeyReq.json();

      addLog("Calling snarkjs.groth16.verify...");
      const res = await snarkjs.groth16.verify(vkey, publicSignals, proof);
      
      const endTime = performance.now();
      const duration = (endTime - startTime).toFixed(2);

      addLog(`Verification Finished in ${duration}ms. Result: ${res}`);
      setVerificationResult(res);
    } catch (err) {
      addLog(`Error: ${err.message}`);
      console.error(err);
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="container mt-5">
      <div className="card shadow-sm">
        <div className="card-header bg-primary text-white">
          <h2 className="mb-0">ZK Proof Generator (Ballot Proof)</h2>
        </div>
        <div className="card-body">
          <div className="mb-4">
            <button 
              className="btn btn-success me-2" 
              onClick={generateProof} 
              disabled={loading}
            >
              {loading ? 'Processing...' : 'Generate Proof'}
            </button>
            <button 
              className="btn btn-info" 
              onClick={verifyProof} 
              disabled={loading || !proof}
            >
              Verify Proof
            </button>
          </div>

          {verificationResult !== null && (
            <div className={`alert ${verificationResult ? 'alert-success' : 'alert-danger'}`}>
              <strong>Verification Result:</strong> {verificationResult ? "VALID" : "INVALID"}
            </div>
          )}

          <div className="row">
            <div className="col-md-6">
              <h5>Logs</h5>
              <div className="bg-light p-3 border rounded" style={{ height: '300px', overflowY: 'auto', fontFamily: 'monospace', fontSize: '0.9rem' }}>
                {logs.length === 0 && <span className="text-muted">No logs yet...</span>}
                {logs.map((log, i) => (
                  <div key={i} className="text-truncate">{log}</div>
                ))}
              </div>
            </div>
            <div className="col-md-6">
              <h5>Proof Data</h5>
              <div className="bg-light p-3 border rounded" style={{ height: '300px', overflowY: 'auto', fontFamily: 'monospace', fontSize: '0.8rem' }}>
                {proof ? (
                  <pre>{JSON.stringify(proof, null, 2)}</pre>
                ) : (
                  <span className="text-muted">No proof generated yet...</span>
                )}
              </div>
            </div>
          </div>
        </div>
        <div className="card-footer text-muted">
          Using snarkjs & groth16
        </div>
      </div>
    </div>
  );
}

export default App;