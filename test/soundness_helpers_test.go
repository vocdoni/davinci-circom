package test

// Witness-level tooling for the soundness tests (soundness_*_test.go).
//
// The question these tests ask is not "does the witness calculator refuse an
// input" but "does a satisfying witness exist": the calculator is untrusted,
// so a witness is checked against the R1CS directly (checkR1CS) and, for the
// decisive cases, by `snarkjs wtns check` as well. Witnesses are produced by
// the calculator and then edited wire by wire through the .sym names.
//
// Two compilations of the unchanged circuits/ballot_proof.circom are used:
//   - the production one (default optimisation), whose r1cs must hash to the
//     value in CEREMONY.md, for the final verdict of every edited witness;
//   - an --O0 one, where every signal is its own wire, so a witness can be
//     edited by signal name and then projected onto the production wires.
//
// Build output lives in test/soundness_out (gitignored).

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math/big"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"testing"

	"github.com/consensys/gnark-crypto/ecc/bn254/fr"
	"github.com/consensys/gnark-crypto/ecc/bn254/twistededwards"
	"github.com/vocdoni/davinci-circom/test/testutils"
	spechash "github.com/vocdoni/davinci-node/spec/hash"
	specutil "github.com/vocdoni/davinci-node/spec/util"
)

// ceremonyR1CSHash is the sha256 of ballot_proof.r1cs in CEREMONY.md: every
// production-level verdict below is about this exact constraint system.
const ceremonyR1CSHash = "07cacd88e84229a1d563a2f88707f24814feb17c1e8788016dbcc672250ee120"

const (
	soundnessOut  = "soundness_out"
	nBallotFields = 16
	nPublic       = 71
)

// bn254r is the BN254 scalar field modulus (the circuit's field).
var bn254r = fr.Modulus()

// babyJubOrder is the prime order of the BabyJubJub subgroup (l).
var babyJubOrder, _ = new(big.Int).SetString("2736030358979909402780800718157159386076813972158567259200215660948447373041", 10)

func bigPow2(n uint) *big.Int { return new(big.Int).Lsh(big.NewInt(1), n) }

func modR(x *big.Int) *big.Int { return new(big.Int).Mod(x, bn254r) }

// ---------------------------------------------------------------------------
// Build: circom compilation and artifact discovery.

var (
	buildOnce sync.Once
	buildErr  error
	build     struct {
		root, out      string
		snarkjs        string
		prodR1CS       string
		prodSym        string
		prodWasm       string
		o0R1CS         string
		o0Sym          string
		o0Wasm         string
		elgamalR1CS    string
		elgamalSym     string
		elgamalWasm    string
		prodR1CSSha256 string
	}
)

func circomCompile(root, src, outDir string, o0 bool) error {
	args := []string{src, "--r1cs", "--wasm", "--sym", "-o", outDir, "-l", filepath.Join(root, "circuits"), "-l", filepath.Join(root, "node_modules")}
	if o0 {
		args = append(args, "--O0")
	}
	cmd := exec.Command(filepath.Join(root, "deps", "circom"), args...)
	cmd.Dir = root
	if out, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("circom %s: %v\n%s", src, err, out)
	}
	return nil
}

func fileSha256(path string) (string, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	s := sha256.Sum256(b)
	return hex.EncodeToString(s[:]), nil
}

func exists(p string) bool { _, err := os.Stat(p); return err == nil }

// soundnessBuild compiles (once) everything the soundness tests need and
// pins the production r1cs to the ceremony hash.
func soundnessBuild(t *testing.T) {
	t.Helper()
	buildOnce.Do(func() {
		root, err := filepath.Abs("..")
		if err != nil {
			buildErr = err
			return
		}
		out := filepath.Join(root, "test", soundnessOut)
		build.root, build.out = root, out
		build.snarkjs = filepath.Join(root, "node_modules", "snarkjs", "build", "cli.cjs")
		if !exists(build.snarkjs) {
			buildErr = fmt.Errorf("snarkjs not found at %s", build.snarkjs)
			return
		}
		if err := os.MkdirAll(out, 0o755); err != nil {
			buildErr = err
			return
		}

		build.prodR1CS = filepath.Join(out, "ballot_proof.r1cs")
		build.prodSym = filepath.Join(out, "ballot_proof.sym")
		build.prodWasm = filepath.Join(out, "ballot_proof_js", "ballot_proof.wasm")
		if !exists(build.prodR1CS) || !exists(build.prodSym) || !exists(build.prodWasm) {
			if err := circomCompile(root, "circuits/ballot_proof.circom", out, false); err != nil {
				buildErr = err
				return
			}
		}
		build.prodR1CSSha256, err = fileSha256(build.prodR1CS)
		if err != nil {
			buildErr = err
			return
		}
		if build.prodR1CSSha256 != ceremonyR1CSHash {
			buildErr = fmt.Errorf("%s hashes to %s, CEREMONY.md says %s (compile with deps/circom 2.1.6)", build.prodR1CS, build.prodR1CSSha256, ceremonyR1CSHash)
			return
		}

		o0 := filepath.Join(out, "o0")
		build.o0R1CS = filepath.Join(o0, "ballot_proof.r1cs")
		build.o0Sym = filepath.Join(o0, "ballot_proof.sym")
		build.o0Wasm = filepath.Join(o0, "ballot_proof_js", "ballot_proof.wasm")
		if !exists(build.o0R1CS) || !exists(build.o0Sym) || !exists(build.o0Wasm) {
			_ = os.MkdirAll(o0, 0o755)
			if err := circomCompile(root, "circuits/ballot_proof.circom", o0, true); err != nil {
				buildErr = err
				return
			}
		}

		eg := filepath.Join(out, "elgamal_bits")
		build.elgamalR1CS = filepath.Join(eg, "soundness_elgamal_bits.r1cs")
		build.elgamalSym = filepath.Join(eg, "soundness_elgamal_bits.sym")
		build.elgamalWasm = filepath.Join(eg, "soundness_elgamal_bits_js", "soundness_elgamal_bits.wasm")
		if !exists(build.elgamalR1CS) || !exists(build.elgamalSym) || !exists(build.elgamalWasm) {
			_ = os.MkdirAll(eg, 0o755)
			if err := circomCompile(root, "test/soundness_elgamal_bits.circom", eg, true); err != nil {
				buildErr = err
				return
			}
		}
	})
	if buildErr != nil {
		t.Fatal(buildErr)
	}
}

// ---------------------------------------------------------------------------
// R1CS and witness files (iden3 binary formats).

type term struct {
	wire int
	coef *big.Int
}

type constraint struct{ a, b, c []term }

type constraintSystem struct {
	nWires      int
	nPubIn      int
	constraints []constraint
}

func readU32(r *bytes.Reader) (uint32, error) {
	var v uint32
	err := binary.Read(r, binary.LittleEndian, &v)
	return v, err
}

func readU64(r *bytes.Reader) (uint64, error) {
	var v uint64
	err := binary.Read(r, binary.LittleEndian, &v)
	return v, err
}

func readFieldLE(r *bytes.Reader, n8 int) (*big.Int, error) {
	buf := make([]byte, n8)
	if _, err := r.Read(buf); err != nil {
		return nil, err
	}
	for i, j := 0, len(buf)-1; i < j; i, j = i+1, j-1 {
		buf[i], buf[j] = buf[j], buf[i]
	}
	return new(big.Int).SetBytes(buf), nil
}

var r1csCache sync.Map

func loadR1CS(t *testing.T, path string) *constraintSystem {
	t.Helper()
	if v, ok := r1csCache.Load(path); ok {
		return v.(*constraintSystem)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	r := bytes.NewReader(data)
	magic := make([]byte, 4)
	_, _ = r.Read(magic)
	if string(magic) != "r1cs" {
		t.Fatalf("%s: bad magic %q", path, magic)
	}
	if _, err := readU32(r); err != nil { // version
		t.Fatal(err)
	}
	nSections, _ := readU32(r)
	type section struct {
		typ   uint32
		start int64
		size  uint64
	}
	var sections []section
	for i := uint32(0); i < nSections; i++ {
		typ, _ := readU32(r)
		size, _ := readU64(r)
		start, _ := r.Seek(0, 1)
		sections = append(sections, section{typ, start, size})
		if _, err := r.Seek(int64(size), 1); err != nil {
			t.Fatal(err)
		}
	}
	out := &constraintSystem{}
	n8 := 0
	var nConstraints uint32
	for _, s := range sections {
		if s.typ == 1 {
			_, _ = r.Seek(s.start, 0)
			v, _ := readU32(r)
			n8 = int(v)
			prime, _ := readFieldLE(r, n8)
			if prime.Cmp(bn254r) != 0 {
				t.Fatalf("%s: prime is not the BN254 scalar field", path)
			}
			nw, _ := readU32(r)
			out.nWires = int(nw)
			_, _ = readU32(r) // nPubOut
			npi, _ := readU32(r)
			out.nPubIn = int(npi)
			_, _ = readU32(r) // nPrvIn
			_, _ = readU64(r) // nLabels
			nConstraints, _ = readU32(r)
		}
	}
	for _, s := range sections {
		if s.typ != 2 {
			continue
		}
		_, _ = r.Seek(s.start, 0)
		readLC := func() []term {
			n, _ := readU32(r)
			lc := make([]term, n)
			for i := range lc {
				w, _ := readU32(r)
				v, _ := readFieldLE(r, n8)
				lc[i] = term{int(w), v}
			}
			return lc
		}
		out.constraints = make([]constraint, nConstraints)
		for i := range out.constraints {
			out.constraints[i] = constraint{readLC(), readLC(), readLC()}
		}
	}
	if len(out.constraints) == 0 {
		t.Fatalf("%s: no constraints section", path)
	}
	r1csCache.Store(path, out)
	return out
}

func evalLC(lc []term, w []*big.Int) *big.Int {
	acc := new(big.Int)
	tmp := new(big.Int)
	for _, tm := range lc {
		tmp.Mul(tm.coef, w[tm.wire])
		acc.Add(acc, tmp)
	}
	return acc.Mod(acc, bn254r)
}

// checkR1CS returns the indices of the constraints the witness violates
// (at most 16, which is enough to locate a problem) and the total count.
func checkR1CS(r *constraintSystem, w []*big.Int) (failing []int, total int) {
	for i, c := range r.constraints {
		a := evalLC(c.a, w)
		b := evalLC(c.b, w)
		cc := evalLC(c.c, w)
		ab := new(big.Int).Mul(a, b)
		ab.Mod(ab, bn254r)
		if ab.Cmp(cc) != 0 {
			total++
			if len(failing) < 16 {
				failing = append(failing, i)
			}
		}
	}
	return failing, total
}

// witnessSatisfies is the production-level verdict used by the tests.
func witnessSatisfies(t *testing.T, r *constraintSystem, w []*big.Int) bool {
	t.Helper()
	if len(w) != r.nWires {
		t.Fatalf("witness has %d wires, r1cs has %d", len(w), r.nWires)
	}
	if w[0].Cmp(big.NewInt(1)) != 0 {
		t.Fatalf("witness[0] must be 1")
	}
	failing, total := checkR1CS(r, w)
	if total > 0 {
		t.Logf("%d constraints violated, first: %v", total, failing)
	}
	return total == 0
}

func readWtns(t *testing.T, path string) []*big.Int {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	r := bytes.NewReader(data)
	magic := make([]byte, 4)
	_, _ = r.Read(magic)
	if string(magic) != "wtns" {
		t.Fatalf("%s: bad magic %q", path, magic)
	}
	_, _ = readU32(r) // version
	nSections, _ := readU32(r)
	var w []*big.Int
	n8 := 0
	for i := uint32(0); i < nSections; i++ {
		typ, _ := readU32(r)
		size, _ := readU64(r)
		start, _ := r.Seek(0, 1)
		switch typ {
		case 1:
			v, _ := readU32(r)
			n8 = int(v)
			_, _ = readFieldLE(r, n8)
			n, _ := readU32(r)
			w = make([]*big.Int, n)
		case 2:
			for j := range w {
				w[j], _ = readFieldLE(r, n8)
			}
		}
		_, _ = r.Seek(start+int64(size), 0)
	}
	return w
}

func writeWtns(t *testing.T, path string, w []*big.Int) {
	t.Helper()
	const n8 = 32
	var buf bytes.Buffer
	buf.WriteString("wtns")
	_ = binary.Write(&buf, binary.LittleEndian, uint32(2))
	_ = binary.Write(&buf, binary.LittleEndian, uint32(2))
	// section 1: header
	_ = binary.Write(&buf, binary.LittleEndian, uint32(1))
	_ = binary.Write(&buf, binary.LittleEndian, uint64(4+n8+4))
	_ = binary.Write(&buf, binary.LittleEndian, uint32(n8))
	buf.Write(fieldLE(bn254r))
	_ = binary.Write(&buf, binary.LittleEndian, uint32(len(w)))
	// section 2: values
	_ = binary.Write(&buf, binary.LittleEndian, uint32(2))
	_ = binary.Write(&buf, binary.LittleEndian, uint64(len(w)*n8))
	for _, v := range w {
		buf.Write(fieldLE(modR(v)))
	}
	if err := os.WriteFile(path, buf.Bytes(), 0o644); err != nil {
		t.Fatal(err)
	}
}

func fieldLE(v *big.Int) []byte {
	b := make([]byte, 32)
	v.FillBytes(b)
	for i, j := 0, len(b)-1; i < j; i, j = i+1, j-1 {
		b[i], b[j] = b[j], b[i]
	}
	return b
}

// loadSym maps every signal name of a .sym file to its wire (-1 when the
// optimiser removed it).
var symCache sync.Map

func loadSym(t *testing.T, path string) map[string]int {
	t.Helper()
	if v, ok := symCache.Load(path); ok {
		return v.(map[string]int)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	m := make(map[string]int, 400000)
	for _, line := range strings.Split(string(data), "\n") {
		parts := strings.SplitN(line, ",", 4)
		if len(parts) != 4 {
			continue
		}
		w, err := strconv.Atoi(parts[1])
		if err != nil {
			continue
		}
		m[parts[3]] = w
	}
	symCache.Store(path, m)
	return m
}

// ---------------------------------------------------------------------------
// snarkjs drivers.

var assertFailedRe = regexp.MustCompile(`Error in template ([A-Za-z0-9_]+)[^\n]*line: (\d+)`)

// calcWitness runs the wasm witness calculator. A non-nil error is the
// calculator refusing the input (its runtime `===` checks), which says
// nothing about whether another witness exists.
func calcWitness(t *testing.T, wasm string, inputs map[string]any) ([]*big.Int, error) {
	t.Helper()
	dir := t.TempDir()
	in, err := json.Marshal(inputs)
	if err != nil {
		t.Fatal(err)
	}
	inPath := filepath.Join(dir, "input.json")
	wtnsPath := filepath.Join(dir, "witness.wtns")
	if err := os.WriteFile(inPath, in, 0o644); err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command("node", build.snarkjs, "wtns", "calculate", wasm, inPath, wtnsPath)
	out, err := cmd.CombinedOutput()
	if err != nil {
		msg := string(out)
		if m := assertFailedRe.FindStringSubmatch(msg); m != nil {
			msg = fmt.Sprintf("assert failed in template %s line %s", m[1], m[2])
		}
		return nil, fmt.Errorf("calculator: %s", strings.TrimSpace(msg))
	}
	return readWtns(t, wtnsPath), nil
}

// snarkjsWtnsCheck runs `snarkjs wtns check` and takes the verdict from its
// log line rather than the exit status (TestSoundnessSnarkjsCheckExitCode
// pins the status of snarkjs 0.7.6; a wrapper or an older version may lose it).
func snarkjsWtnsCheck(t *testing.T, r1csPath string, w []*big.Int) (ok bool, exitCode int) {
	t.Helper()
	wtnsPath := filepath.Join(t.TempDir(), "edited.wtns")
	writeWtns(t, wtnsPath, w)
	cmd := exec.Command("node", build.snarkjs, "wtns", "check", r1csPath, wtnsPath)
	out, err := cmd.CombinedOutput()
	if err != nil {
		if ee, isExit := err.(*exec.ExitError); isExit {
			exitCode = ee.ExitCode()
		} else {
			t.Fatalf("snarkjs wtns check: %v\n%s", err, out)
		}
	}
	s := string(out)
	switch {
	case strings.Contains(s, "WITNESS IS CORRECT"):
		return true, exitCode
	case strings.Contains(s, "WITNESS IS NOT CORRECT"):
		return false, exitCode
	}
	t.Fatalf("snarkjs wtns check: no verdict in output\n%s", s)
	return false, exitCode
}

// ---------------------------------------------------------------------------
// Ballot inputs.

// ballotMode is the circuit's packed layout (ballot_protocol.circom,
// GenesisLib.sol, davinci-sdk crypto/ballot.ts). Not spec.BallotMode.Pack,
// see TestSoundnessSpecPackLayout.
type ballotMode struct {
	NumFields    uint8
	GroupSize    uint8
	UniqueValues bool
	CostExponent uint8
	MaxValue     uint64 // < 2^48
	MinValue     uint64 // < 2^48
	MaxValueSum  uint64 // < 2^63, 0 = the voter weight
	MinValueSum  uint64 // < 2^63
}

func (m ballotMode) pack() *big.Int {
	p := new(big.Int).SetUint64(uint64(m.NumFields))
	or := func(v *big.Int, shift uint) { p.Or(p, new(big.Int).Lsh(v, shift)) }
	or(new(big.Int).SetUint64(uint64(m.GroupSize)), 8)
	if m.UniqueValues {
		or(big.NewInt(1), 16)
	}
	or(new(big.Int).SetUint64(uint64(m.CostExponent)), 17)
	or(new(big.Int).SetUint64(m.MaxValue), 25)
	or(new(big.Int).SetUint64(m.MinValue), 73)
	or(new(big.Int).SetUint64(m.MaxValueSum), 121)
	or(new(big.Int).SetUint64(m.MinValueSum), 184)
	return p
}

// simpleMode is a one-field mode: value in [0, maxValue], exponent 1, min sums
// 0, max sum from the weight when maxValueSum is 0.
func simpleMode(numFields uint8, maxValue, maxValueSum uint64, exp uint8) ballotMode {
	return ballotMode{NumFields: numFields, GroupSize: numFields, CostExponent: exp, MaxValue: maxValue, MaxValueSum: maxValueSum}
}

type ballotCase struct {
	mode         ballotMode
	packed       *big.Int
	fields       []*big.Int // 16 entries
	weight       *big.Int
	sk, pubX     *big.Int
	pubY         *big.Int
	k            *big.Int
	ks           []*big.Int // Poseidon chain, ks[0] = k
	cipherfields [][2][2]*big.Int
	processID    *big.Int
	address      *big.Int
	voteID       *big.Int
}

func randomField(t *testing.T) *big.Int {
	t.Helper()
	k, err := specutil.RandomK()
	if err != nil {
		t.Fatal(err)
	}
	return k
}

// newBallotCase builds the honest inputs of a ballot: fields are encrypted
// with the Poseidon chain of k, slots at or above NumFields carry the TE
// identity the SDKs and the zkVM guest use, the vote id is the spec one.
// Fields are taken as given (any integer; values that cannot be encrypted
// are still passed to the calculator, which must then refuse them).
func newBallotCase(t *testing.T, mode ballotMode, fields []*big.Int, weight *big.Int) *ballotCase {
	t.Helper()
	if len(fields) > nBallotFields {
		t.Fatalf("%d fields", len(fields))
	}
	b := &ballotCase{mode: mode, packed: mode.pack(), weight: weight}
	b.fields = make([]*big.Int, nBallotFields)
	for i := range b.fields {
		b.fields[i] = new(big.Int)
		if i < len(fields) {
			b.fields[i].Set(fields[i])
		}
	}
	b.sk, b.pubX, b.pubY = testutils.GenerateKeyPair()
	b.k = randomField(t)
	var err error
	b.ks, err = spechash.DerivePoseidonChain(b.k, nBallotFields)
	if err != nil {
		t.Fatal(err)
	}
	b.cipherfields = make([][2][2]*big.Int, nBallotFields)
	for i := range b.cipherfields {
		if i < int(mode.NumFields) && b.fields[i].Sign() >= 0 && b.fields[i].BitLen() <= 48 {
			c1, c2 := testutils.Encrypt(b.fields[i], b.pubX, b.pubY, b.ks[i+1])
			b.cipherfields[i] = [2][2]*big.Int{{new(big.Int).Set(&c1[0]), new(big.Int).Set(&c1[1])}, {new(big.Int).Set(&c2[0]), new(big.Int).Set(&c2[1])}}
		} else {
			b.cipherfields[i] = [2][2]*big.Int{{big.NewInt(0), big.NewInt(1)}, {big.NewInt(0), big.NewInt(1)}}
		}
	}
	b.processID = new(big.Int).SetBytes(randomBytesN(20))
	b.address = new(big.Int).SetBytes(randomBytesN(20))
	b.voteID, err = spechash.VoteID(b.processID, b.address, b.k)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func randomBytesN(n int) []byte {
	b := make([]byte, n)
	for i := 0; i < n; i += 32 {
		x, _ := specutil.RandomK()
		copy(b[i:], x.FillBytes(make([]byte, 32)))
	}
	return b
}

func (b *ballotCase) inputs() map[string]any {
	fields := make([]string, nBallotFields)
	for i, f := range b.fields {
		fields[i] = modR(f).String()
	}
	return map[string]any{
		"address":            b.address.String(),
		"vote_id":            b.voteID.String(),
		"process_id":         b.processID.String(),
		"packed_ballot_mode": b.packed.String(),
		"encryption_pubkey":  []string{b.pubX.String(), b.pubY.String()},
		"weight":             modR(b.weight).String(),
		"cipherfields":       testutils.StringifyCipherfields(b.cipherfields),
		"fields":             fields,
		"k":                  b.k.String(),
	}
}

func ints(vs ...int64) []*big.Int {
	out := make([]*big.Int, len(vs))
	for i, v := range vs {
		out[i] = big.NewInt(v)
	}
	return out
}

// ---------------------------------------------------------------------------
// Edited witnesses: O0 witness by name, projected onto the production wires.

// setByName sets the O0 wire of a signal; the name must exist.
func setByName(t *testing.T, sym map[string]int, w []*big.Int, name string, v *big.Int) {
	t.Helper()
	wire, ok := sym[name]
	if !ok || wire < 0 {
		t.Fatalf("signal %s not found", name)
	}
	w[wire] = modR(v)
}

func getByName(t *testing.T, sym map[string]int, w []*big.Int, name string) *big.Int {
	t.Helper()
	wire, ok := sym[name]
	if !ok || wire < 0 {
		t.Fatalf("signal %s not found", name)
	}
	return w[wire]
}

// projectWitness maps an O0 witness onto the production wire set by signal
// name. Several O0 signals share one production wire (the optimiser merged
// them); they must carry the same value or the O0 witness is inconsistent.
func projectWitness(t *testing.T, o0Sym, prodSym map[string]int, prod *constraintSystem, w0 []*big.Int) []*big.Int {
	t.Helper()
	w := make([]*big.Int, prod.nWires)
	w[0] = big.NewInt(1) // the constant wire has no sym entry
	for name, pw := range prodSym {
		if pw < 0 {
			continue
		}
		ow, ok := o0Sym[name]
		if !ok {
			t.Fatalf("signal %s only in the production sym", name)
		}
		v := w0[ow]
		if w[pw] == nil {
			w[pw] = v
		} else if w[pw].Cmp(v) != 0 {
			t.Fatalf("production wire %d gets %s and %s from %s", pw, w[pw], v, name)
		}
	}
	for i, v := range w {
		if v == nil {
			t.Fatalf("production wire %d unassigned", i)
		}
	}
	return w
}

// ---------------------------------------------------------------------------
// BabyJubJub helpers (TE coordinates, circom convention).

func teToPoint(x, y *big.Int) twistededwards.PointAffine {
	xr, yr := testutils.FromTEtoRTE(x, y)
	var p twistededwards.PointAffine
	p.X.SetBigInt(xr)
	p.Y.SetBigInt(yr)
	return p
}

func pointToTE(p twistededwards.PointAffine) (*big.Int, *big.Int) {
	return testutils.FromRTEtoTE(p.X.BigInt(new(big.Int)), p.Y.BigInt(new(big.Int)))
}

// elgamalDecrypt returns c2 - sk*c1 in TE coordinates.
func elgamalDecrypt(sk *big.Int, c [2][2]*big.Int) (*big.Int, *big.Int) {
	c1 := teToPoint(c[0][0], c[0][1])
	c2 := teToPoint(c[1][0], c[1][1])
	var s, neg twistededwards.PointAffine
	s.ScalarMultiplication(&c1, sk)
	neg.Neg(&s)
	var m twistededwards.PointAffine
	m.Add(&c2, &neg)
	return pointToTE(m)
}

// scalarBaseTE returns m*G in TE coordinates.
func scalarBaseTE(m *big.Int) (*big.Int, *big.Int) {
	curve := twistededwards.GetEdwardsCurve()
	var p twistededwards.PointAffine
	p.ScalarMultiplication(&curve.Base, m)
	return pointToTE(p)
}

func bitsOf(v *big.Int, n int) []*big.Int {
	out := make([]*big.Int, n)
	for i := range out {
		out[i] = big.NewInt(int64(v.Bit(i)))
	}
	return out
}

func bitStrings(bits []*big.Int) []string {
	out := make([]string, len(bits))
	for i, b := range bits {
		out[i] = b.String()
	}
	return out
}

// compileTestCircuit compiles test/<name>.circom (--O0, once) into
// soundness_out/<name>/ and returns the r1cs, sym and wasm paths.
var testCircuitOnce sync.Map

func compileTestCircuit(t *testing.T, name string) (r1csPath, symPath, wasmPath string) {
	t.Helper()
	soundnessBuild(t)
	dir := filepath.Join(build.out, name)
	r1csPath = filepath.Join(dir, name+".r1cs")
	symPath = filepath.Join(dir, name+".sym")
	wasmPath = filepath.Join(dir, name+"_js", name+".wasm")
	once, _ := testCircuitOnce.LoadOrStore(name, new(sync.Once))
	var err error
	once.(*sync.Once).Do(func() {
		if exists(r1csPath) && exists(symPath) && exists(wasmPath) {
			return
		}
		_ = os.MkdirAll(dir, 0o755)
		err = circomCompile(build.root, filepath.Join("test", name+".circom"), dir, true)
	})
	if err != nil {
		t.Fatal(err)
	}
	if !exists(r1csPath) {
		t.Fatalf("%s not built", r1csPath)
	}
	return
}

func mustVoteID(t *testing.T, b *ballotCase) *big.Int {
	t.Helper()
	v, err := spechash.VoteID(b.processID, b.address, b.k)
	if err != nil {
		t.Fatal(err)
	}
	return v
}

// setK replaces k, its Poseidon chain, the ciphertexts and the vote id.
func (b *ballotCase) setK(t *testing.T, k *big.Int) {
	t.Helper()
	b.k = new(big.Int).Set(k)
	var err error
	b.ks, err = spechash.DerivePoseidonChain(b.k, nBallotFields)
	if err != nil {
		t.Fatal(err)
	}
	b.recomputeCiphertexts(t)
	b.voteID = mustVoteID(t, b)
}

// recomputeCiphertexts re-encrypts the active fields with the current key,
// chain and public key (skipping messages that cannot be encoded, and
// public keys that are not valid points, which keep the identity).
func (b *ballotCase) recomputeCiphertexts(t *testing.T) {
	t.Helper()
	pub := teToPoint(b.pubX, b.pubY)
	for i := range b.cipherfields {
		b.cipherfields[i] = [2][2]*big.Int{{big.NewInt(0), big.NewInt(1)}, {big.NewInt(0), big.NewInt(1)}}
		if i < int(b.mode.NumFields) && b.fields[i].Sign() >= 0 && b.fields[i].BitLen() <= 48 && pub.IsOnCurve() {
			c1, c2 := testutils.Encrypt(b.fields[i], b.pubX, b.pubY, b.ks[i+1])
			b.cipherfields[i] = [2][2]*big.Int{{new(big.Int).Set(&c1[0]), new(big.Int).Set(&c1[1])}, {new(big.Int).Set(&c2[0]), new(big.Int).Set(&c2[1])}}
		}
	}
}
