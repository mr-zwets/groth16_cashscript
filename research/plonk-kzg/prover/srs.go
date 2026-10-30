package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"

	"github.com/consensys/gnark-crypto/ecc"
	curve "github.com/consensys/gnark-crypto/ecc/bn254"
	"github.com/consensys/gnark-crypto/ecc/bn254/fr"
	kzgbn254 "github.com/consensys/gnark-crypto/ecc/bn254/kzg"
	"github.com/consensys/gnark/constraint"
	"github.com/consensys/gnark/test/unsafekzg"
)

// The Aztec Ignition [x]_2 in gnark's raw (EVM) order x.c1 | x.c0 | y.c1 | y.c0; ceremony/main.go verifies it
// against the ceremony and checks the G1 powers against it.
const ignitionTau2 = "260e01b251f6f1c7e7ff4e580791dee8ea51d87a358e038b4efe30fac09383c1" +
	"0118c4d5b837bcc2bc89b5b398b5974e9f5944073b32078b7e231fec938883b0" +
	"04fc6369f7110fe3d25156c1bb9a72859cf2a04641f99ba4ee413c80da6a5fe4" +
	"22febda3c0c0632a56475b4214e5615e11e6dd3f96e6cea2854a87d4dacc5e55"

// sha256 of the SRS file ./ceremony writes, per G1 point count (the file is deterministic: kzg.SRS.WriteTo of the
// verified points). -log 16 gives 65,539 points (srs/ignition_bn254_65539.json). A file of another size is not pinned;
// it is accepted only after the power check below, which circuitSRS runs on every slice it uses anyway.
var pinnedSRSSha = map[int]string{
	65539: "ee63bf8e2f8d4c9d55eb2ceb716da116e99b170cdb51ce39b279b1b555edbb85",
}

type loadedSRS struct {
	srs    *kzgbn254.SRS
	sha256 string
}

var ceremonySRS *loadedSRS

// loadSRS reads the file ./ceremony wrote and re-checks [1]_1, [1]_2, the pinned [x]_2 and G1[0] = [1]_1, and
// the file's sha256 against pinnedSRSSha (panics on a mismatch). circuitSRS also re-runs the power check of
// ./ceremony on the n+3 points each circuit uses, so the G1 table is checked here, not only trusted.
func loadSRS(path string) *loadedSRS {
	b, err := os.ReadFile(path)
	must(err)
	var s kzgbn254.SRS
	_, err = s.ReadFrom(bytes.NewReader(b))
	must(err)
	_, _, g1, g2 := curve.Generators()
	t2 := s.Vk.G2[1].RawBytes()
	if !s.Vk.G1.Equal(&g1) || !s.Pk.G1[0].Equal(&g1) || !s.Vk.G2[0].Equal(&g2) || hex.EncodeToString(t2[:]) != ignitionTau2 {
		panic(path + ": not the Ignition SRS ([1]_1, [1]_2 or [x]_2 differ)")
	}
	h := sha256.Sum256(b)
	if want, ok := pinnedSRSSha[len(s.Pk.G1)]; ok {
		if hex.EncodeToString(h[:]) != want {
			panic(fmt.Sprintf("%s: sha256 %x is not the pinned %s for %d points", path, h, want, len(s.Pk.G1)))
		}
	} else {
		fmt.Printf("SRS %s: %d points, no pinned sha256 for this size (power check per circuit only)\n", path, len(s.Pk.G1))
	}
	fmt.Printf("SRS %s: %d G1 points, sha256 %s\n", path, len(s.Pk.G1), hex.EncodeToString(h[:]))
	return &loadedSRS{srs: &s, sha256: hex.EncodeToString(h[:])}
}

// circuitSRS returns the canonical SRS (n+3 points, as unsafekzg sizes it) and its Lagrange form (n points).
func circuitSRS(ccs constraint.ConstraintSystem) (*kzgbn254.SRS, *kzgbn254.SRS, map[string]any) {
	n := ecc.NextPowerOfTwo(uint64(ccs.GetNbConstraints() + ccs.GetNbPublicVariables()))
	if ceremonySRS == nil {
		c, l, err := unsafekzg.NewSRS(ccs, unsafekzg.WithToxicSeed([]byte(toxicSeed)))
		must(err)
		return c.(*kzgbn254.SRS), l.(*kzgbn254.SRS), map[string]any{
			"unsafe":    true,
			"toxicSeed": toxicSeed,
			"note":      "unsafekzg.WithToxicSeed: tau is derived from the seed, so anyone can forge proofs; test vectors only",
			"g1Points":  n + 3,
		}
	}
	all := ceremonySRS.srs
	if uint64(len(all.Pk.G1)) < n+3 {
		panic(fmt.Sprintf("circuit needs n = %d, so %d SRS points; the SRS file has %d (rebuild it with ./ceremony -log)", n, n+3, len(all.Pk.G1)))
	}
	checkPowers(all.Pk.G1[:n+3], all.Vk.G2[1])
	canonical := &kzgbn254.SRS{Pk: kzgbn254.ProvingKey{G1: all.Pk.G1[:n+3]}, Vk: all.Vk}
	lg, err := kzgbn254.ToLagrangeG1(all.Pk.G1[:n])
	must(err)
	lagrange := &kzgbn254.SRS{Pk: kzgbn254.ProvingKey{G1: lg}, Vk: all.Vk}
	return canonical, lagrange, map[string]any{
		"unsafe":     false,
		"ceremony":   "Aztec Ignition (MAIN IGNITION: 176 participants 2019-10-25..2019-12-17, then sealed); see FORMAT.md SRS and srs/",
		"tau2Raw":    ignitionTau2,
		"srsFileSha": ceremonySRS.sha256,
		"srsPoints":  len(all.Pk.G1),
		"g1Points":   n + 3,
		"note":       "[x^0..x^(n+2)]_1 of the sealed Ignition transcript, power-checked against [x]_2 by ceremony/main.go; Lagrange form by gnark-crypto kzg.ToLagrangeG1",
	}
}

// checkPowers: P[i] = [x^i]_1 for all i, given P[0] = [1]_1 (checked by loadSRS) and [x]_2, by one random linear
// combination (as ceremony/main.go step 6): e(sum r_i P_i, [x]_2) == e(sum r_i P_(i+1), [1]_2), r_i from crypto/rand.
// A control with [1]_2 in place of [x]_2 must fail.
func checkPowers(P []curve.G1Affine, t2 curve.G2Affine) {
	_, _, _, g2 := curve.Generators()
	r := make([]fr.Element, len(P)-1)
	for i := range r {
		_, err := r[i].SetRandom()
		must(err)
	}
	var L1, L2 curve.G1Affine
	_, err := L1.MultiExp(P[:len(P)-1], r, ecc.MultiExpConfig{})
	must(err)
	_, err = L2.MultiExp(P[1:], r, ecc.MultiExpConfig{})
	must(err)
	pair := func(a2 curve.G2Affine) bool {
		var na2 curve.G2Affine
		na2.Neg(&a2)
		ok, err := curve.PairingCheck([]curve.G1Affine{L1, L2}, []curve.G2Affine{na2, g2})
		must(err)
		return ok
	}
	if !pair(t2) || pair(g2) {
		panic(fmt.Sprintf("SRS power check failed on %d points", len(P)))
	}
	fmt.Printf("SRS power check: %d points are [x^i]_1 for the pinned [x]_2 (control fails)\n", len(P))
}
