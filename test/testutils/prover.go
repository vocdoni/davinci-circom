package testutils

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
)

type ProofData struct {
	A        []string   `json:"pi_a"`
	B        [][]string `json:"pi_b"`
	C        []string   `json:"pi_c"`
	Protocol string     `json:"protocol"`
	Curve    string     `json:"curve"`
}

func getSnarkJSPath() (string, error) {
	// Look for locally installed snarkjs in node_modules
	path, err := filepath.Abs("../node_modules/snarkjs/build/cli.cjs")
	if err == nil {
		if _, err := os.Stat(path); err == nil {
			return path, nil
		}
	}
    // Try current dir
	path, err = filepath.Abs("node_modules/snarkjs/build/cli.cjs")
	if err == nil {
		if _, err := os.Stat(path); err == nil {
			return path, nil
		}
	}
    
    // Try global/path executable
    path, err = exec.LookPath("snarkjs")
    if err == nil {
        return path, nil
    }

	return "", fmt.Errorf("snarkjs not found")
}

func CompileAndGenerateProof(inputs []byte, wasmFile, zkeyFile string) (string, string, error) {
	// Create temp dir for execution
	tempDir, err := os.MkdirTemp("", "snarkjs_test")
	if err != nil {
		return "", "", err
	}
	defer func() { _ = os.RemoveAll(tempDir) }()

	inputPath := filepath.Join(tempDir, "input.json")
	if err := os.WriteFile(inputPath, inputs, 0o644); err != nil {
		return "", "", err
	}

	witnessPath := filepath.Join(tempDir, "witness.wtns")
	proofPath := filepath.Join(tempDir, "proof.json")
	publicPath := filepath.Join(tempDir, "public.json")

	// Generate witness using snarkjs
	snarkjsPath, err := getSnarkJSPath()
	if err != nil {
		return "", "", err
	}

    // Determine how to call snarkjs (node script or binary)
    var cmdWtns *exec.Cmd
    if filepath.Ext(snarkjsPath) == ".cjs" || filepath.Ext(snarkjsPath) == ".js" {
        cmdWtns = exec.Command("node", snarkjsPath, "wtns", "calculate", wasmFile, inputPath, witnessPath)
    } else {
        cmdWtns = exec.Command(snarkjsPath, "wtns", "calculate", wasmFile, inputPath, witnessPath)
    }

	if out, err := cmdWtns.CombinedOutput(); err != nil {
		return "", "", fmt.Errorf("snarkjs wtns calculate failed: %v\nOutput: %s", err, out)
	}

	// Generate proof
    var cmdProve *exec.Cmd
    if filepath.Ext(snarkjsPath) == ".cjs" || filepath.Ext(snarkjsPath) == ".js" {
        cmdProve = exec.Command("node", snarkjsPath, "groth16", "prove", zkeyFile, witnessPath, proofPath, publicPath)
    } else {
        cmdProve = exec.Command(snarkjsPath, "groth16", "prove", zkeyFile, witnessPath, proofPath, publicPath)
    }

	if out, err := cmdProve.CombinedOutput(); err != nil {
		return "", "", fmt.Errorf("snarkjs groth16 prove failed: %v\nOutput: %s", err, out)
	}

	// Read results
	proofBytes, err := os.ReadFile(proofPath)
	if err != nil {
		return "", "", err
	}
	publicBytes, err := os.ReadFile(publicPath)
	if err != nil {
		return "", "", err
	}

	return string(proofBytes), string(publicBytes), nil
}

func VerifyProof(proofData, pubSignals string, vkey []byte) error {
	tempDir, err := os.MkdirTemp("", "snarkjs_verify")
	if err != nil {
		return err
	}
	defer func() { _ = os.RemoveAll(tempDir) }()

	proofPath := filepath.Join(tempDir, "proof.json")
	publicPath := filepath.Join(tempDir, "public.json")
	vkeyPath := filepath.Join(tempDir, "vkey.json")

	if err := os.WriteFile(proofPath, []byte(proofData), 0o644); err != nil {
		return err
	}
	if err := os.WriteFile(publicPath, []byte(pubSignals), 0o644); err != nil {
		return err
	}
	if err := os.WriteFile(vkeyPath, vkey, 0o644); err != nil {
		return err
	}

	snarkjsPath, err := getSnarkJSPath()
	if err != nil {
		return err
	}

    var cmdVerify *exec.Cmd
    if filepath.Ext(snarkjsPath) == ".cjs" || filepath.Ext(snarkjsPath) == ".js" {
        cmdVerify = exec.Command("node", snarkjsPath, "groth16", "verify", vkeyPath, publicPath, proofPath)
    } else {
        cmdVerify = exec.Command(snarkjsPath, "groth16", "verify", vkeyPath, publicPath, proofPath)
    }

	if out, err := cmdVerify.CombinedOutput(); err != nil {
		return fmt.Errorf("snarkjs groth16 verify failed: %v\nOutput: %s", err, out)
	}

	return nil
}