package testutils

import (
	"crypto/rand"
	"encoding/json"
	"math/big"
	"strconv"

	"github.com/vocdoni/davinci-node/spec"
	spechash "github.com/vocdoni/davinci-node/spec/hash"
	spectestutil "github.com/vocdoni/davinci-node/spec/testutil"
	specutil "github.com/vocdoni/davinci-node/spec/util"
)

// ballotFieldCapacity is the compile-time field capacity of the ballot
// circuit. It must match the BallotProof(N) instantiation in
// circuits/ballot_proof.circom. It is deliberately not read from
// spec/params.FieldsPerBallot: the pinned davinci-node/spec release still
// reports 8 while this circuit is compiled at 16. Switch back to the spec
// constant once a davinci-node release ships FieldsPerBallot=16.
const ballotFieldCapacity = 16

// BallotVectors holds a reproducible set of inputs for the ballot circuits.
type BallotVectors struct {
	Fields       []int
	Weight       int
	PubKeyX      *big.Int
	PubKeyY      *big.Int
	Cipherfields [][2][2]*big.Int
	ProcessID    *big.Int
	Address      *big.Int
	K            *big.Int
	VoteID       uint64
	spec.BallotMode
	PackedBallot *big.Int
}

func randomBytes(n int) []byte {
	b := make([]byte, n)
	_, _ = rand.Read(b)
	return b
}

// BuildBallotVectors creates fresh valid inputs matching the circom ballot circuits.
func BuildBallotVectors() (*BallotVectors, error) {
	bm := spectestutil.FixedBallotMode()
	packedBallot, err := bm.Pack()
	if err != nil {
		return nil, err
	}
	nFields := ballotFieldCapacity

	fields := make([]int, nFields)
	for i := range int(bm.NumFields) {
		fields[i] = i + 1
	}
	weight := 1

	_, pubX, pubY := GenerateKeyPair()

	k, err := specutil.RandomK()
	if err != nil {
		return nil, err
	}

	ks, err := spechash.DerivePoseidonChain(k, nFields)
	if err != nil {
		return nil, err
	}

	cipherfields := make([][2][2]*big.Int, nFields)
	for i := range nFields {
		c1, c2 := Encrypt(big.NewInt(int64(fields[i])), pubX, pubY, ks[i+1])
		cipherfields[i] = [2][2]*big.Int{
			{new(big.Int).Set(&c1[0]), new(big.Int).Set(&c1[1])},
			{new(big.Int).Set(&c2[0]), new(big.Int).Set(&c2[1])},
		}
	}

	processID := new(big.Int).SetBytes(randomBytes(20))
	address := new(big.Int).SetBytes(randomBytes(20))

	voteID, err := spec.VoteID(processID, address, k)
	if err != nil {
		return nil, err
	}

	return &BallotVectors{
		Fields:       fields,
		Weight:       weight,
		PubKeyX:      pubX,
		PubKeyY:      pubY,
		Cipherfields: cipherfields,
		ProcessID:    processID,
		Address:      address,
		K:            k,
		VoteID:       voteID,
		BallotMode:   bm,
		PackedBallot: packedBallot,
	}, nil
}

// InputsMap returns the JSON-friendly map expected by snarkjs/ballot circuits.
func (b *BallotVectors) InputsMap() map[string]any {
	return map[string]any{
		"fields":             b.Fields,
		"weight":             b.Weight,
		"encryption_pubkey":  []string{b.PubKeyX.String(), b.PubKeyY.String()},
		"cipherfields":       StringifyCipherfields(b.Cipherfields),
		"process_id":         b.ProcessID.String(),
		"address":            b.Address.String(),
		"k":                  b.K.String(),
		"vote_id":            strconv.FormatUint(b.VoteID, 10),
		"packed_ballot_mode": b.PackedBallot.String(),
	}
}

// PublicSignals returns the 71 public signals in circuit order: address,
// vote_id, process_id, packed_ballot_mode, encryption_pubkey x and y, weight,
// then c1.x, c1.y, c2.x, c2.y of every cipherfield.
func (b *BallotVectors) PublicSignals() []string {
	out := []string{
		b.Address.String(),
		strconv.FormatUint(b.VoteID, 10),
		b.ProcessID.String(),
		b.PackedBallot.String(),
		b.PubKeyX.String(),
		b.PubKeyY.String(),
		strconv.Itoa(b.Weight),
	}
	for _, cf := range b.Cipherfields {
		out = append(out, cf[0][0].String(), cf[0][1].String(), cf[1][0].String(), cf[1][1].String())
	}
	return out
}

// MarshalInputs returns the circom input JSON bytes.
func (b *BallotVectors) MarshalInputs() ([]byte, error) {
	return json.Marshal(b.InputsMap())
}

// StringifyCipherfields converts big.Int cipherfields to strings for circom input.
func StringifyCipherfields(cf [][2][2]*big.Int) [][2][2]string {
	out := make([][2][2]string, len(cf))
	for i := range cf {
		for j := 0; j < 2; j++ {
			for k := 0; k < 2; k++ {
				out[i][j][k] = cf[i][j][k].String()
			}
		}
	}
	return out
}
