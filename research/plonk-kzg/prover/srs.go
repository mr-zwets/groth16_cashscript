package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"

	"github.com/consensys/gnark-crypto/ecc"
	curve "github.com/consensys/gnark-crypto/ecc/bn254"
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

type loadedSRS struct {
	srs    *kzgbn254.SRS
	sha256 string
}

var ceremonySRS *loadedSRS

// loadSRS reads the file ./ceremony wrote and re-checks its small part: [1]_1, [1]_2, the pinned [x]_2 and
// G1[0] = [1]_1. The power consistency of the G1 table was checked by ./ceremony when it built the file;
// a tampered table would only break proving or give keys that do not verify, not change [x]_2.
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
