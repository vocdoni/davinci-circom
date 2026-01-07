import React, { useState, useEffect } from 'react';
import * as snarkjs from 'snarkjs';
import { BallotBuilder } from '@vocdoni/davinci-circom';

function App() {
  const [logs, setLogs] = useState([]);
  const [proof, setProof] = useState(null);
  const [publicSignals, setPublicSignals] = useState(null);
  const [verificationResult, setVerificationResult] = useState(null);
  const [loading, setLoading] = useState(false);
  const [errorMsg, setErrorMsg] = useState(null);
  const [singleThread, setSingleThread] = useState(false);

  // Form State
  const [fieldsStr, setFieldsStr] = useState("1, 2, 3, 4, 5");
  const [weight, setWeight] = useState(1);
  const [processId, setProcessId] = useState("1234567890123456789012345678901234567890"); // ~20 bytes hex-ish
  const [address, setAddress] = useState("1234567890123456789012345678901234567890");
  const [k, setK] = useState(""); // Generated or manual
  
  // Config State
  const [config, setConfig] = useState({
    numFields: 8,
    uniqueValues: 1,
    maxValue: 16,
    minValue: 0,
    maxValueSum: 1125,
    minValueSum: 5,
    costExponent: 2,
    costFromWeight: 0
  });

  const addLog = (msg, type = 'info') => {
    const timestamp = new Date().toLocaleTimeString();
    setLogs((prev) => [{ timestamp, msg, type }, ...prev]);
  };

  const generateK = async () => {
    try {
      addLog(`Generating K (SingleThread: ${singleThread})...`);
      const builder = await BallotBuilder.build(singleThread);
      const newK = builder.randomK();
      setK(newK);
      addLog("Generated new random K", "success");
    } catch (err) {
      addLog(`Error generating K: ${err.message}`, "error");
    }
  };

  // Helper to parse hex or decimal string to decimal string
  const toDecimal = (str) => {
    try {
      if (str.startsWith("0x")) {
        return BigInt(str).toString();
      }
      return BigInt(str).toString();
    } catch (e) {
      throw new Error(`Invalid number format: ${str}`);
    }
  };

  const generateProof = async () => {
    setLoading(true);
    setErrorMsg(null);
    setVerificationResult(null);
    setLogs([]); // Clear logs
    addLog("Starting Proof Generation in Worker...");

    try {
        // Parse Inputs in Main Thread
        const fieldsArr = fieldsStr.split(',').map(s => parseInt(s.trim())).filter(n => !isNaN(n));
        
        let procIdDec = "0";
        try { procIdDec = toDecimal(processId.startsWith("0x") ? processId : "0x" + processId); } 
        catch { procIdDec = toDecimal(processId); }
        
        let addrDec = "0";
        try { addrDec = toDecimal(address.startsWith("0x") ? address : "0x" + address); } 
        catch { addrDec = toDecimal(address); }

        // Fetch Artifacts in Main Thread to avoid Worker path issues
        addLog("Fetching artifacts...");
        const wasmUrl = 'ballot_proof.wasm';
        const zkeyUrl = 'ballot_proof_pkey.zkey';

        const [wasmResp, zkeyResp] = await Promise.all([
            fetch(wasmUrl),
            fetch(zkeyUrl)
        ]);

        if (!wasmResp.ok) throw new Error(`WASM fetch failed: ${wasmResp.status}`);
        if (!zkeyResp.ok) throw new Error(`ZKey fetch failed: ${zkeyResp.status}`);

        const wasmBuffer = await wasmResp.arrayBuffer();
        const zkeyBuffer = await zkeyResp.arrayBuffer();
        addLog(`Artifacts loaded. WASM: ${wasmBuffer.byteLength}, ZKey: ${zkeyBuffer.byteLength}`, "success");

        const worker = new Worker(new URL('./worker.js', import.meta.url), { type: 'module' });

        worker.postMessage({
            type: 'generateProof',
            singleThread,
            args: {
                fieldsArr,
                weight,
                processId: procIdDec,
                address: addrDec,
                k,
                config
            },
            wasm: wasmBuffer,
            zkey: zkeyBuffer
        }, [wasmBuffer, zkeyBuffer]); // Transfer buffers

        worker.onmessage = (e) => {
            const { type, msg, style, proof: resProof, publicSignals: resSignals, generatedK } = e.data;
            
            if (type === 'log') {
                addLog(msg, style);
            } else if (type === 'error') {
                const errMsg = `Worker Error: ${msg}`;
                addLog(errMsg, 'error');
                setErrorMsg(errMsg);
                setLoading(false);
                worker.terminate();
            } else if (type === 'result') {
                setProof(resProof);
                setPublicSignals(resSignals);
                if (generatedK && !k) setK(generatedK);
                setLoading(false);
                worker.terminate();
            }
        };

        worker.onerror = (e) => {
            const msg = `Worker execution failed: ${e.message}`;
            addLog(msg, 'error');
            setErrorMsg(msg);
            setLoading(false);
        };

    } catch (err) {
        const msg = `Pre-computation Failed: ${err.message}`;
        addLog(msg, 'error');
        setErrorMsg(msg);
        setLoading(false);
    }
  };


  const verifyProof = async () => {
    if (!proof || !publicSignals) {
      addLog("No proof to verify.", "error");
      return;
    }
    setLoading(true);
    setErrorMsg(null);
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

      addLog(`Verification Finished in ${duration}ms. Result: ${res}`, res ? "success" : "error");
      setVerificationResult(res);
    } catch (err) {
      const msg = `Verification Failed: ${err.message}`;
      addLog(msg, "error");
      setErrorMsg(msg);
      console.error(err);
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="container mt-5 mb-5">
      <div className="card shadow-sm">
        <div className="card-header bg-primary text-white">
          <h2 className="mb-0">ZK Proof Generator (Ballot Proof)</h2>
        </div>
        <div className="card-body">
          
          <div className="row mb-3">
            <div className="col-12 col-md-6 mb-2 mb-md-0">
                <label className="form-label">Vote Choices (comma separated)</label>
                <input type="text" className="form-control" value={fieldsStr} onChange={e => setFieldsStr(e.target.value)} />
            </div>
            <div className="col-12 col-md-6">
                <label className="form-label">Weight</label>
                <input type="number" className="form-control" value={weight} onChange={e => setWeight(parseInt(e.target.value))} />
            </div>
          </div>

          <div className="row mb-3">
            <div className="col-12 col-md-4 mb-2 mb-md-0">
                <label className="form-label">Process ID (Hex/Dec)</label>
                <input type="text" className="form-control" value={processId} onChange={e => setProcessId(e.target.value)} />
            </div>
            <div className="col-12 col-md-4 mb-2 mb-md-0">
                <label className="form-label">Address (Hex/Dec)</label>
                <input type="text" className="form-control" value={address} onChange={e => setAddress(e.target.value)} />
            </div>
            <div className="col-12 col-md-4">
                <label className="form-label">Random K</label>
                <div className="input-group">
                    <input type="text" className="form-control" value={k} onChange={e => setK(e.target.value)} placeholder="Auto-generated if empty" />
                    <button className="btn btn-outline-secondary" onClick={generateK}>Gen</button>
                </div>
            </div>
          </div>

          <div className="card mb-4 bg-light">
            <div className="card-body">
              <h5 className="card-title">Ballot Configuration</h5>
              <div className="row g-3">
                <div className="col-6 col-md-3">
                  <label className="form-label">Unique Values</label>
                  <select className="form-select" value={config.uniqueValues} onChange={e => setConfig({...config, uniqueValues: parseInt(e.target.value)})}>
                    <option value="1">Enabled (1)</option>
                    <option value="0">Disabled (0)</option>
                  </select>
                </div>
                <div className="col-6 col-md-3">
                  <label className="form-label">Max Value</label>
                  <input type="number" className="form-control" value={config.maxValue} onChange={e => setConfig({...config, maxValue: parseInt(e.target.value)})} />
                </div>
                <div className="col-6 col-md-3">
                  <label className="form-label">Min Value</label>
                  <input type="number" className="form-control" value={config.minValue} onChange={e => setConfig({...config, minValue: parseInt(e.target.value)})} />
                </div>
                <div className="col-6 col-md-3">
                  <label className="form-label">Cost Exponent</label>
                  <input type="number" className="form-control" value={config.costExponent} onChange={e => setConfig({...config, costExponent: parseInt(e.target.value)})} />
                </div>
                <div className="col-6 col-md-3">
                  <label className="form-label">Max Value Sum</label>
                  <input type="number" className="form-control" value={config.maxValueSum} onChange={e => setConfig({...config, maxValueSum: parseInt(e.target.value)})} />
                </div>
                <div className="col-6 col-md-3">
                  <label className="form-label">Min Value Sum</label>
                  <input type="number" className="form-control" value={config.minValueSum} onChange={e => setConfig({...config, minValueSum: parseInt(e.target.value)})} />
                </div>
                <div className="col-6 col-md-3">
                  <label className="form-label">Cost From Weight</label>
                  <select className="form-select" value={config.costFromWeight} onChange={e => setConfig({...config, costFromWeight: parseInt(e.target.value)})}>
                    <option value="0">Disabled (0)</option>
                    <option value="1">Enabled (1)</option>
                  </select>
                </div>
                <div className="col-6 col-md-3">
                  <label className="form-label">Capacity</label>
                  <input type="text" className="form-control" value="8 (Fixed)" disabled />
                </div>
                <div className="col-12 mt-3">
                  <div className="form-check">
                    <input 
                      className="form-check-input" 
                      type="checkbox" 
                      id="singleThreadCheck" 
                      checked={singleThread} 
                      onChange={e => setSingleThread(e.target.checked)} 
                    />
                    <label className="form-check-label" htmlFor="singleThreadCheck">
                      Force Single-Threaded Mode (Recommended for Mobile to prevent crashes)
                    </label>
                  </div>
                </div>
              </div>
            </div>
          </div>

          <div className="mb-4 d-grid gap-2 d-md-block">
            <button 
              className="btn btn-success me-md-2" 
              onClick={generateProof} 
              disabled={loading}
            >
              {loading ? 'Processing...' : 'Compute Inputs & Generate Proof'}
            </button>
            <button 
              className="btn btn-info" 
              onClick={verifyProof} 
              disabled={loading || !proof}
            >
              Verify Proof
            </button>
          </div>

          {errorMsg && (
            <div className="alert alert-danger text-break">
              <strong>Error:</strong> {errorMsg}
            </div>
          )}

          {verificationResult !== null && (
            <div className={`alert ${verificationResult ? 'alert-success' : 'alert-danger'}`}>
              <strong>Verification Result:</strong> {verificationResult ? "VALID" : "INVALID"}
            </div>
          )}

          <div className="row">
            <div className="col-12 col-md-6 mb-3 mb-md-0">
              <h5>Logs</h5>
              <div className="bg-light p-3 border rounded" style={{ height: '300px', overflowY: 'auto', overflowX: 'auto', fontFamily: 'monospace', fontSize: '0.9rem' }}>
                {logs.length === 0 && <span className="text-muted">No logs yet...</span>}
                {logs.map((log, i) => (
                  <div key={i} className={`text-nowrap ${log.type === 'success' ? 'text-success fw-bold' : log.type === 'error' ? 'text-danger' : ''}`}>
                    [{log.timestamp}] {log.msg}
                  </div>
                ))}
              </div>
            </div>
            <div className="col-12 col-md-6">
              <h5>Proof Data</h5>
              <div className="bg-light p-3 border rounded" style={{ height: '300px', overflowY: 'auto', overflowX: 'auto', fontFamily: 'monospace', fontSize: '0.8rem' }}>
                {proof ? (
                  <pre>{JSON.stringify(proof, null, 2)}</pre>
                ) : (
                  <span className="text-muted">No proof generated yet...</span>
                )}
              </div>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}

export default App;
