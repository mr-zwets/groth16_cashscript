package main

import (
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"math/big"

	curve "github.com/consensys/gnark-crypto/ecc/bn254"
	"github.com/consensys/gnark-crypto/ecc/bn254/fp"
	"github.com/consensys/gnark-crypto/ecc/bn254/fr"
	plonkbn254 "github.com/consensys/gnark/backend/plonk/bn254"
)

// Proof layout (gnark MarshalSolidity, no BSB22 commitments): 768 bytes.
var pointNames = []string{"L", "R", "O", "H0", "H1", "H2", "Z", "Wzeta", "WzetaOmega"}
var pointOffsets = []int{0, 64, 128, 192, 256, 320, 544, 640, 704}
var scalarNames = []string{"l_zeta", "r_zeta", "o_zeta", "s1_zeta", "s2_zeta", "z_zetaOmega"}
var scalarOffsets = []int{384, 416, 448, 480, 512, 608}

func g1Raw(p *curve.G1Affine) []byte { b := p.RawBytes(); return b[:] }
func g2Raw(p *curve.G2Affine) []byte { b := p.RawBytes(); return b[:] }
func frRaw(e *fr.Element) []byte     { b := e.Bytes(); return b[:] }

// encodeVK: see FORMAT.md "Verifying key" (944 bytes).
func encodeVK(vk *plonkbn254.VerifyingKey) []byte {
	var out []byte
	out = binary.BigEndian.AppendUint64(out, vk.Size)
	out = binary.BigEndian.AppendUint64(out, vk.NbPublicVariables)
	out = append(out, frRaw(&vk.Generator)...)
	out = append(out, frRaw(&vk.SizeInv)...)
	out = append(out, frRaw(&vk.CosetShift)...)
	for _, p := range []*curve.G1Affine{&vk.S[0], &vk.S[1], &vk.S[2], &vk.Ql, &vk.Qr, &vk.Qm, &vk.Qo, &vk.Qk} {
		out = append(out, g1Raw(p)...)
	}
	out = append(out, g1Raw(&vk.Kzg.G1)...)
	out = append(out, g2Raw(&vk.Kzg.G2[0])...)
	out = append(out, g2Raw(&vk.Kzg.G2[1])...)
	// v2-bsb22 (FORMAT.md "BSB22 commitments"): only when the circuit has commitments, so v1 keys stay 944 bytes
	if len(vk.Qcp) > 0 {
		out = binary.BigEndian.AppendUint64(out, uint64(len(vk.Qcp)))
		for i := range vk.Qcp {
			out = binary.BigEndian.AppendUint64(out, vk.CommitmentConstraintIndexes[i])
			out = append(out, g1Raw(&vk.Qcp[i])...)
		}
	}
	return out
}

func g1Dec(p *curve.G1Affine) map[string]string {
	var x, y big.Int
	p.X.BigInt(&x)
	p.Y.BigInt(&y)
	return map[string]string{"x": x.String(), "y": y.String()}
}

func fpDec(e fp.Element) string { var b big.Int; e.BigInt(&b); return b.String() }

func g2Dec(p *curve.G2Affine) map[string]any {
	return map[string]any{
		"x": map[string]string{"c0": fpDec(p.X.A0), "c1": fpDec(p.X.A1)},
		"y": map[string]string{"c0": fpDec(p.Y.A0), "c1": fpDec(p.Y.A1)},
	}
}

func vkFields(vk *plonkbn254.VerifyingKey) map[string]any {
	qcp := make([]map[string]string, len(vk.Qcp))
	for i := range vk.Qcp {
		qcp[i] = g1Dec(&vk.Qcp[i])
	}
	return map[string]any{
		"Qcp": qcp, "commitmentConstraintIndexes": vk.CommitmentConstraintIndexes,
		"n": vk.Size, "nbPublic": vk.NbPublicVariables,
		"omega": frBig(vk.Generator).String(), "nInv": frBig(vk.SizeInv).String(), "cosetShift": frBig(vk.CosetShift).String(),
		"S1": g1Dec(&vk.S[0]), "S2": g1Dec(&vk.S[1]), "S3": g1Dec(&vk.S[2]),
		"Ql": g1Dec(&vk.Ql), "Qr": g1Dec(&vk.Qr), "Qm": g1Dec(&vk.Qm), "Qo": g1Dec(&vk.Qo), "Qk": g1Dec(&vk.Qk),
		"g1": g1Dec(&vk.Kzg.G1), "g2": g2Dec(&vk.Kzg.G2[0]), "g2x": g2Dec(&vk.Kzg.G2[1]),
	}
}

func cloneProof(p *plonkbn254.Proof) *plonkbn254.Proof {
	q := *p
	q.Bsb22Commitments = append([]curve.G1Affine(nil), p.Bsb22Commitments...)
	q.BatchedProof.ClaimedValues = append([]fr.Element(nil), p.BatchedProof.ClaimedValues...)
	return &q
}

func pointRef(p *plonkbn254.Proof, i int) *curve.G1Affine {
	switch i {
	case 0, 1, 2:
		return &p.LRO[i]
	case 3, 4, 5:
		return &p.H[i-3]
	case 6:
		return &p.Z
	case 7:
		return &p.BatchedProof.H
	case 8:
		return &p.ZShiftedOpening.H
	default:
		return &p.Bsb22Commitments[i-9]
	}
}

func scalarRef(p *plonkbn254.Proof, i int) *fr.Element {
	if i < 5 {
		return &p.BatchedProof.ClaimedValues[i+1]
	}
	if i == 5 {
		return &p.ZShiftedOpening.ClaimedValue
	}
	return &p.BatchedProof.ClaimedValues[i] // i >= 6: qcp_j(zeta), j = i - 6
}

// proofLayout returns the point and scalar names and byte offsets of a MarshalSolidity proof with m commitments:
// 768 bytes as in v1, then m scalars qcp_j(zeta) (32 B), then m points Bsb22_j (64 B).
func proofLayout(m int) (pn []string, po []int, sn []string, so []int) {
	pn, po = append([]string(nil), pointNames...), append([]int(nil), pointOffsets...)
	sn, so = append([]string(nil), scalarNames...), append([]int(nil), scalarOffsets...)
	for j := 0; j < m; j++ {
		sn, so = append(sn, fmt.Sprintf("qcp%d_zeta", j)), append(so, 768+32*j)
		pn, po = append(pn, fmt.Sprintf("Bsb22_%d", j)), append(po, 768+32*m+64*j)
	}
	return
}

var rBig = fr.Modulus()
var pBig = fp.Modulus()

func put32(b []byte, off int, v *big.Int) {
	if v.BitLen() > 256 {
		panic("put32 overflow")
	}
	for i := 0; i < 32; i++ {
		b[off+i] = 0
	}
	v.FillBytes(b[off : off+32])
}

func get32(b []byte, off int) *big.Int { return new(big.Int).SetBytes(b[off : off+32]) }

func makeTampered(vk *plonkbn254.VerifyingKey, proofs []*plonkbn254.Proof, pubs [][]fr.Element) []tamperedProof {
	var out []tamperedProof
	base := proofs[0]
	pub0 := pubs[0]
	baseBytes := base.MarshalSolidity()
	var gen curve.G1Affine
	_, _, gen, _ = curve.Generators()
	pointNames, pointOffsets, scalarNames, scalarOffsets := proofLayout(len(vk.Qcp))

	addStruct := func(name, class string, p *plonkbn254.Proof, pub []fr.Element) {
		out = append(out, tamperedProof{Name: name, Class: class, Base: 0, PublicInputs: hexFrs(pub),
			Proof: hex.EncodeToString(p.MarshalSolidity()), Expect: "reject", Gnark: gnarkVerify(vk, p, pub)})
	}
	addBytes := func(name, class string, proof []byte, pubHex []string) {
		out = append(out, tamperedProof{Name: name, Class: class, Base: 0, PublicInputs: pubHex,
			Proof: hex.EncodeToString(proof), Expect: "reject", Gnark: "n/a"})
	}

	// 1. every proof point: replaced by another valid point (P+G, -P, infinity)
	for i, name := range pointNames {
		q := cloneProof(base)
		pointRef(q, i).Add(pointRef(q, i), &gen)
		addStruct("point."+name+".plusG", "point-value", q, pub0)
		q = cloneProof(base)
		pointRef(q, i).Neg(pointRef(q, i))
		addStruct("point."+name+".negated", "point-value", q, pub0)
		q = cloneProof(base)
		pointRef(q, i).SetInfinity()
		addStruct("point."+name+".infinity", "point-infinity", q, pub0)
	}
	// 2. every proof scalar + 1
	for i, name := range scalarNames {
		q := cloneProof(base)
		one := fr.One()
		scalarRef(q, i).Add(scalarRef(q, i), &one)
		addStruct("scalar."+name+".plus1", "scalar-value", q, pub0)
	}
	// 3. every public input + 1, and a swap
	for i := range pub0 {
		pub := append([]fr.Element(nil), pub0...)
		one := fr.One()
		pub[i].Add(&pub[i], &one)
		addStruct(fmt.Sprintf("pi.%d.plus1", i), "public-input", base, pub)
	}
	if len(pub0) >= 2 {
		pub := append([]fr.Element(nil), pub0...)
		pub[0], pub[1] = pub[1], pub[0]
		addStruct("pi.swap01", "public-input", base, pub)
	}
	// 4. a valid proof presented with another proof's public inputs
	if len(proofs) > 1 {
		addStruct("mix.proof1-with-pi0", "mix", proofs[1], pub0)
	}
	// 5. BSB22: proof 0 with the commitment (and, separately, also qcp(zeta)) of proof 1; and the commitment point
	// moved by an honest-looking amount (2C, C - G) so only the hash-to-field / PI term or the KZG check can catch it
	if len(vk.Qcp) > 0 && len(proofs) > 1 {
		q := cloneProof(base)
		q.Bsb22Commitments[0] = proofs[1].Bsb22Commitments[0]
		addStruct("bsb22.commitment-from-proof1", "commitment", q, pub0)
		q = cloneProof(base)
		q.Bsb22Commitments[0] = proofs[1].Bsb22Commitments[0]
		q.BatchedProof.ClaimedValues[6] = proofs[1].BatchedProof.ClaimedValues[6]
		addStruct("bsb22.commitment-and-qcp-from-proof1", "commitment", q, pub0)
		q = cloneProof(base)
		q.Bsb22Commitments[0].Double(&q.Bsb22Commitments[0])
		addStruct("bsb22.commitment-doubled", "commitment", q, pub0)
		q = cloneProof(base)
		q.Bsb22Commitments[0].Sub(&q.Bsb22Commitments[0], &gen)
		addStruct("bsb22.commitment-minusG", "commitment", q, pub0)
		q = cloneProof(base)
		q.BatchedProof.ClaimedValues[6].SetZero()
		addStruct("bsb22.qcp-zeta-zero", "commitment", q, pub0)
	}

	// byte-level encodings that gnark's structs cannot represent
	pub0Hex := hexFrs(pub0)
	for i, name := range pointNames {
		off := pointOffsets[i]
		b := append([]byte(nil), baseBytes...)
		y := get32(b, off+32)
		y.Add(y, big.NewInt(1)).Mod(y, pBig)
		put32(b, off+32, y)
		addBytes("point."+name+".offCurve", "point-encoding", b, pub0Hex)
		b = append([]byte(nil), baseBytes...)
		x := get32(b, off)
		put32(b, off, x.Add(x, pBig))
		addBytes("point."+name+".xPlusP", "point-encoding", b, pub0Hex)
		b = append([]byte(nil), baseBytes...)
		y = get32(b, off+32)
		put32(b, off+32, y.Add(y, pBig))
		addBytes("point."+name+".yPlusP", "point-encoding", b, pub0Hex)
	}
	for i, name := range scalarNames {
		b := append([]byte(nil), baseBytes...)
		s := get32(b, scalarOffsets[i])
		put32(b, scalarOffsets[i], s.Add(s, rBig))
		addBytes("scalar."+name+".plusR", "scalar-encoding", b, pub0Hex)
	}
	for i := range pub0 {
		pub := append([]string(nil), pub0Hex...)
		v := frBig(pub0[i])
		v.Add(v, rBig)
		var w [32]byte
		v.FillBytes(w[:])
		pub[i] = hex.EncodeToString(w[:])
		addBytes(fmt.Sprintf("pi.%d.plusR", i), "public-input-encoding", baseBytes, pub)
	}
	addBytes("size.truncated", "size", baseBytes[:len(baseBytes)-1], pub0Hex)
	addBytes("size.extended", "size", append(append([]byte(nil), baseBytes...), 0), pub0Hex)
	addBytes("pi.count.dropLast", "size", baseBytes, pub0Hex[:len(pub0Hex)-1])
	addBytes("pi.count.extraZero", "size", baseBytes, append(append([]string(nil), pub0Hex...), hex.EncodeToString(make([]byte, 32))))
	return out
}
