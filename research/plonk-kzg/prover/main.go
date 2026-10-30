// Command prover builds gnark PLONK (KZG, BN254) proofs for two circuits and writes JSON vectors in the
// byte format of FORMAT.md: a VK, several valid proofs per circuit, and tampered variants.
//
//	GOMAXPROCS=4 nice go run . -out vectors -proofs 5
//
// The SRS is a TEST (unsafe) SRS with a known toxic value, see FORMAT.md "SRS".
package main

import (
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"math/big"
	"math/rand/v2"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/consensys/gnark-crypto/ecc"
	curve "github.com/consensys/gnark-crypto/ecc/bn254"
	"github.com/consensys/gnark-crypto/ecc/bn254/fr"
	"github.com/consensys/gnark-crypto/ecc/bn254/fr/hash_to_field"
	nmimc "github.com/consensys/gnark-crypto/ecc/bn254/fr/mimc"
	kzgbn254 "github.com/consensys/gnark-crypto/ecc/bn254/kzg"
	"github.com/consensys/gnark/backend/plonk"
	plonkbn254 "github.com/consensys/gnark/backend/plonk/bn254"
	"github.com/consensys/gnark/backend/witness"
	"github.com/consensys/gnark/constraint"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/scs"
	"github.com/consensys/gnark/logger"
	"github.com/consensys/gnark/test/unsafekzg"
)

const (
	gnarkVersion       = "v0.16.4"
	gnarkCryptoVersion = "v0.21.1-0.20260913224755-1409fe592052"
	toxicSeed          = "verifier.cash plonk-kzg TEST SRS v1 (unsafe, toxic value is public)"
	formatID           = "plonk-kzg-bn254/v1"
	formatIDCommit     = "plonk-kzg-bn254/v2-bsb22" // v1 plus BSB22 commitments, FORMAT.md "BSB22 commitments"
)

func must(err error) {
	if err != nil {
		panic(err)
	}
}

func main() {
	out := flag.String("out", "vectors", "output directory")
	nProofs := flag.Int("proofs", 5, "valid proofs per circuit")
	seed := flag.Uint64("seed", 20261029, "witness seed (gnark's blinding randomness is not seeded)")
	only := flag.String("circuits", "mul2,merkle16", "comma-separated circuits to build (mul2, merkle16, range64, merkle16rc)")
	flag.Parse()
	logger.Disable()
	must(os.MkdirAll(*out, 0o755))
	rng := rand.New(rand.NewPCG(*seed, 0x706c6f6e6b))

	var srsVK *srsInfo
	all := map[string]func() circuitDef{"mul2": mulDef, "merkle16": merkleDef, "range64": range64Def, "merkle16rc": merkleRangeDef}
	for _, name := range strings.Split(*only, ",") {
		mk, ok := all[name]
		if !ok {
			panic("unknown circuit " + name)
		}
		c := mk()
		// each circuit gets its own witness stream, so building a subset reproduces the same witnesses
		crng := rand.New(rand.NewPCG(*seed, hashName(name)))
		if name == "mul2" || name == "merkle16" {
			crng = rng // the v1 vectors used one shared stream: keep it for byte-compatible regeneration
		}
		info := runCircuit(c, *nProofs, crng, *out)
		if srsVK == nil {
			srsVK = info
		} else if *srsVK != *info {
			panic("the circuits do not share the same SRS verifier points")
		}
	}
	fmt.Println("all circuits share the SRS verifier points [1]_1, [1]_2, [x]_2:", srsVK.G2x[:16]+"...")
}

type circuitDef struct {
	name      string
	statement string
	circuit   frontend.Circuit
	// commitments is the expected number of BSB22 (api.Commit) commitments in the VK
	commitments int
	// assign returns a satisfying full assignment and its public input values.
	assign func(rng *rand.Rand) (frontend.Circuit, []fr.Element)
}

type srsInfo struct{ G1, G2, G2x string }

func randFr(rng *rand.Rand) fr.Element {
	var b [32]byte
	for i := range b {
		b[i] = byte(rng.UintN(256))
	}
	var e fr.Element
	e.SetBytes(b[:]) // reduces mod r
	return e
}

func mulDef() circuitDef {
	return circuitDef{
		name:      "mul2",
		statement: "public n0, n1; private a, b with a*b == n0 and a+b == n1 (2 public inputs, the bench Groth16 fixtures' interface)",
		circuit:   &MulCircuit{},
		assign: func(rng *rand.Rand) (frontend.Circuit, []fr.Element) {
			a, b := randFr(rng), randFr(rng)
			var n0, n1 fr.Element
			n0.Mul(&a, &b)
			n1.Add(&a, &b)
			return &MulCircuit{N0: n0, N1: n1, A: a, B: b}, []fr.Element{n0, n1}
		},
	}
}

func mimcHash(xs ...fr.Element) fr.Element {
	h := nmimc.NewMiMC()
	for _, x := range xs {
		b := x.Bytes()
		_, err := h.Write(b[:])
		must(err)
	}
	var e fr.Element
	must(e.SetBytesCanonical(h.Sum(nil)))
	return e
}

func merkleDef() circuitDef {
	return circuitDef{
		name: "merkle16",
		statement: "public root, nullifierHash, context; private nullifier, trapdoor, 16 siblings and index bits; " +
			"nullifierHash == MiMC(nullifier), leaf == MiMC(nullifier, trapdoor), the path from leaf hashes to root " +
			"(MiMC(left, right) per level); context is bound only as a public input",
		circuit: &MerkleCircuit{},
		assign: func(rng *rand.Rand) (frontend.Circuit, []fr.Element) {
			var w MerkleCircuit
			nul, trap, ctx := randFr(rng), randFr(rng), randFr(rng)
			nh := mimcHash(nul)
			cur := mimcHash(nul, trap)
			for i := 0; i < MerkleDepth; i++ {
				sib := randFr(rng)
				bit := rng.UintN(2)
				w.Path[i] = sib
				w.Index[i] = bit
				if bit == 1 {
					cur = mimcHash(sib, cur)
				} else {
					cur = mimcHash(cur, sib)
				}
			}
			w.Root, w.NullifierHash, w.Context = cur, nh, ctx
			w.Nullifier, w.Trapdoor = nul, trap
			return &w, []fr.Element{cur, nh, ctx}
		},
	}
}

type validProof struct {
	PublicInputs []string `json:"publicInputs"`
	Proof        string   `json:"proof"`
	LinOpening   string   `json:"linOpening"`
	// Bsb22Hash: per commitment, gnark's hash_to_field("BSB22-Plonk") of the commitment point (the value the
	// verifier adds to PI(zeta) at the commitment's Lagrange index); omitted without commitments
	Bsb22Hash   []string `json:"bsb22Hash,omitempty"`
	ProveMillis int64    `json:"proveMillis"`
}

type tamperedProof struct {
	Name         string   `json:"name"`
	Class        string   `json:"class"`
	Base         int      `json:"base"`
	PublicInputs []string `json:"publicInputs"`
	Proof        string   `json:"proof"`
	Expect       string   `json:"expect"`
	Gnark        string   `json:"gnark"`
}

type vectorsFile struct {
	Format      string            `json:"format"`
	Gnark       string            `json:"gnark"`
	GnarkCrypto string            `json:"gnarkCrypto"`
	Circuit     map[string]any    `json:"circuit"`
	SRS         map[string]any    `json:"srs"`
	VK          map[string]any    `json:"vk"`
	Valid       []validProof      `json:"valid"`
	Tampered    []tamperedProof   `json:"tampered"`
	Notes       map[string]string `json:"notes"`
}

func runCircuit(c circuitDef, nProofs int, rng *rand.Rand, out string) *srsInfo {
	ccs, err := frontend.Compile(ecc.BN254.ScalarField(), scs.NewBuilder, c.circuit)
	must(err)
	canonical, lagrange, err := unsafekzg.NewSRS(ccs, unsafekzg.WithToxicSeed([]byte(toxicSeed)))
	must(err)
	pkI, vkI, err := plonk.Setup(ccs, canonical, lagrange)
	must(err)
	vk := vkI.(*plonkbn254.VerifyingKey)
	if len(vk.Qcp) != c.commitments {
		panic(fmt.Sprintf("%s: expected %d BSB22 commitments, VK has %d", c.name, c.commitments, len(vk.Qcp)))
	}
	sccs := ccs.(constraint.ConstraintSystem)
	fmt.Printf("%s: %d constraints, %d public, domain n=%d\n", c.name, sccs.GetNbConstraints(), vk.NbPublicVariables, vk.Size)

	vf := vectorsFile{
		Format: formatFor(vk), Gnark: gnarkVersion, GnarkCrypto: gnarkCryptoVersion,
		Circuit: map[string]any{
			"name": c.name, "statement": c.statement,
			"nbConstraints": sccs.GetNbConstraints(), "nbPublic": vk.NbPublicVariables,
			"domainSize": vk.Size, "bsb22Commitments": len(vk.Qcp),
		},
		SRS: map[string]any{
			"unsafe":    true,
			"toxicSeed": toxicSeed,
			"note":      "unsafekzg.WithToxicSeed: tau is derived from the seed, so anyone can forge proofs; test vectors only",
			"g1Points":  len(canonical.(*kzgbn254.SRS).Pk.G1),
		},
		Notes: map[string]string{
			"linOpening": "ClaimedValues[0] of gnark's proof struct (opening of the linearised polynomial at zeta); not part of the 768-byte proof, the verifier recomputes it (verify.mjs cross-checks it equals r0)",
			"proofs":     "gnark's prover blinds with crypto/rand, so re-running gives different (equally valid) proofs",
			"tampered":   "expect is the reference verdict; gnark is gnark's own Verify on the same tampered struct, or n/a for byte-level encodings gnark's structs cannot hold",
		},
	}
	vkHex := encodeVK(vk)
	vf.VK = map[string]any{"hex": hex.EncodeToString(vkHex), "bytes": len(vkHex), "fields": vkFields(vk)}

	var proofs []*plonkbn254.Proof
	var pubs [][]fr.Element
	for i := 0; i < nProofs; i++ {
		assignment, pub := c.assign(rng)
		full, err := frontend.NewWitness(assignment, ecc.BN254.ScalarField())
		must(err)
		pw, err := full.Public()
		must(err)
		t0 := time.Now()
		pI, err := plonk.Prove(ccs, pkI, full)
		must(err)
		ms := time.Since(t0).Milliseconds()
		must(plonk.Verify(pI, vkI, pw))
		p := pI.(*plonkbn254.Proof)
		checkPub(pw, pub)
		proofs = append(proofs, p)
		pubs = append(pubs, pub)
		vf.Valid = append(vf.Valid, validProof{PublicInputs: hexFrs(pub), Proof: hex.EncodeToString(p.MarshalSolidity()),
			LinOpening: hex.EncodeToString(frRaw(&p.BatchedProof.ClaimedValues[0])), Bsb22Hash: bsb22Hashes(p), ProveMillis: ms})
	}
	vf.Tampered = makeTampered(vk, proofs, pubs)
	rejected := 0
	for _, t := range vf.Tampered {
		if t.Gnark == "reject" {
			rejected++
		} else if t.Gnark == "ACCEPT" {
			panic(c.name + ": gnark accepted tampered " + t.Name)
		}
	}
	fmt.Printf("%s: %d valid proofs, %d tampered (%d also checked by gnark Verify, all rejected)\n",
		c.name, len(vf.Valid), len(vf.Tampered), rejected)

	b, err := json.MarshalIndent(vf, "", "  ")
	must(err)
	must(os.WriteFile(filepath.Join(out, c.name+".json"), append(b, '\n'), 0o644))
	return &srsInfo{G1: hex.EncodeToString(g1Raw(&vk.Kzg.G1)), G2: hex.EncodeToString(g2Raw(&vk.Kzg.G2[0])), G2x: hex.EncodeToString(g2Raw(&vk.Kzg.G2[1]))}
}

func checkPub(pw witness.Witness, want []fr.Element) {
	v := pw.Vector().(fr.Vector)
	if len(v) != len(want) {
		panic("public witness length")
	}
	for i := range v {
		if !v[i].Equal(&want[i]) {
			panic("public witness order")
		}
	}
}

func hexFrs(v []fr.Element) []string {
	s := make([]string, len(v))
	for i := range v {
		b := v[i].Bytes()
		s[i] = hex.EncodeToString(b[:])
	}
	return s
}

// gnarkVerify runs gnark's own verifier on a (possibly tampered) proof struct.
func gnarkVerify(vk *plonkbn254.VerifyingKey, p *plonkbn254.Proof, pub []fr.Element) string {
	if err := plonkbn254.Verify(p, vk, fr.Vector(pub)); err != nil {
		return "reject"
	}
	return "ACCEPT"
}

func frBig(e fr.Element) *big.Int { var b big.Int; e.BigInt(&b); return &b }

var _ = curve.G1Affine{}

// bsb22Hashes recomputes the commitment hashes exactly as gnark's Verify does (default HashToFieldFn).
func bsb22Hashes(p *plonkbn254.Proof) []string {
	var out []string
	h := hash_to_field.New([]byte("BSB22-Plonk"))
	for i := range p.Bsb22Commitments {
		h.Write(p.Bsb22Commitments[i].Marshal())
		b := h.Sum(nil)
		h.Reset()
		var e fr.Element
		e.SetBytes(b[:fr.Bytes])
		out = append(out, hex.EncodeToString(frRaw(&e)))
	}
	return out
}

func formatFor(vk *plonkbn254.VerifyingKey) string {
	if len(vk.Qcp) == 0 {
		return formatID
	}
	return formatIDCommit
}

func hashName(s string) uint64 {
	var h uint64 = 1469598103934665603
	for i := 0; i < len(s); i++ {
		h = (h ^ uint64(s[i])) * 1099511628211
	}
	return h
}

func range64Def() circuitDef {
	return circuitDef{
		name:        "range64",
		statement:   "public n0; private a with a*a == n0 and 0 <= a < 2^64 (std/rangecheck: one BSB22 commitment)",
		circuit:     &Range64Circuit{},
		commitments: 1,
		assign: func(rng *rand.Rand) (frontend.Circuit, []fr.Element) {
			var a, n0 fr.Element
			a.SetUint64(rng.Uint64())
			n0.Mul(&a, &a)
			return &Range64Circuit{N0: n0, A: a}, []fr.Element{n0}
		},
	}
}

func merkleRangeDef() circuitDef {
	return circuitDef{
		name: "merkle16rc",
		statement: "merkle16 with a private 64-bit amount in the leaf: public root, nullifierHash, context; " +
			"nullifierHash == MiMC(nullifier), leaf == MiMC(nullifier, trapdoor, amount), 0 <= amount < 2^64 " +
			"(std/rangecheck: one BSB22 commitment), the path from leaf hashes to root (MiMC(left, right) per level)",
		circuit:     &MerkleRangeCircuit{},
		commitments: 1,
		assign: func(rng *rand.Rand) (frontend.Circuit, []fr.Element) {
			var w MerkleRangeCircuit
			nul, trap, ctx := randFr(rng), randFr(rng), randFr(rng)
			var amt fr.Element
			amt.SetUint64(rng.Uint64())
			nh := mimcHash(nul)
			cur := mimcHash(nul, trap, amt)
			for i := 0; i < MerkleDepth; i++ {
				sib := randFr(rng)
				bit := rng.UintN(2)
				w.Path[i] = sib
				w.Index[i] = bit
				if bit == 1 {
					cur = mimcHash(sib, cur)
				} else {
					cur = mimcHash(cur, sib)
				}
			}
			w.Root, w.NullifierHash, w.Context = cur, nh, ctx
			w.Nullifier, w.Trapdoor, w.Amount = nul, trap, amt
			return &w, []fr.Element{cur, nh, ctx}
		},
	}
}
