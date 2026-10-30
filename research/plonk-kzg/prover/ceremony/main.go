// Command ceremony builds a gnark-crypto KZG SRS for BN254 from the Aztec Ignition ceremony (MAIN IGNITION,
// 176 participants, sealed by Aztec), downloading only what is needed, and verifies what it loads.
//
//	GOMAXPROCS=4 nice go run ./ceremony -cache DIR -log 16
//
// What is downloaded (HTTP range requests, cached in DIR; about 3*(2^log)*64 bytes plus 62 KB):
//   - manifest.json (full; its sha256 is pinned below)
//   - for each of the 176 participants: bytes 0..91 (header, first G1 point [x_k]_1) and the two G2 points
//     ([x_k]_2, [z_k]_2) of their transcript00.dat
//   - sealed/transcript00.dat: header, the first N-1 G1 points [x^1..x^{N-1}]_1, the two G2 points
//   - cross-checks: the same prefix of monomial/transcript00.dat and of flat/g1.dat
//
// What is verified:
//  1. manifest sha256 and its crs.t2 equal the pinned [x]_2 (also hardcoded in Aztec's barretenberg verifiers)
//  2. every transcript header (transcript 0 of 20, 100.8M G1 points, 5.04M per file, 2 G2 points, start 0)
//  3. all points on the curve and in the prime-order subgroup
//  4. the chain of the first power over all participants and the seal: for each contribution k,
//     e([x_k]_1, [1]_2) = e([1]_1, [x_k]_2)   and   e([x_k]_1, [1]_2) = e([x_{k-1}]_1, [z_k]_2), x_0 = 1
//  5. the sealed [x]_2 equals the pinned value
//  6. the powers used: with P = ([1]_1, sealed G1[0..N-2]) and random r_i (crypto/rand),
//     e(sum r_i P[i], [x]_2) = e(sum r_i P[i+1], [1]_2), i < N-1, which (with P[0] = [1]_1) gives P[i] = [x^i]_1
//  7. monomial/transcript00.dat and flat/g1.dat hold the same points P
//
// Not verified here (out of the download budget): the full 100.8M-point consistency of every participant's
// transcript, the BLAKE2b checksums of the full files, and the participants' signatures. Aztec's
// ignition-verification and gnark-ignition-verifier do those over the full ~1.1 TB.
package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/consensys/gnark-crypto/ecc"
	curve "github.com/consensys/gnark-crypto/ecc/bn254"
	"github.com/consensys/gnark-crypto/ecc/bn254/fp"
	"github.com/consensys/gnark-crypto/ecc/bn254/fr"
	"github.com/consensys/gnark-crypto/ecc/bn254/kzg"
)

const (
	baseURL         = "https://aztec-ignition.s3.amazonaws.com/MAIN%20IGNITION/"
	manifestSHA256  = "d231a1defd9804721ded32c75dd6f956efbf61c254b3ebcec4bb6596ba9941b8"
	pointsPerFile   = 5040000
	totalG1         = 100800000
	g2Offset        = 28 + pointsPerFile*64 // first transcript: header, G1 points, then 2 G2 points
	nParticipants   = 176
	maxLogDomain    = 26 // n + 3 <= 100,800,001 points (incl. [1]_1) caps n at 2^26
	sealedName      = "sealed/transcript00.dat"
	monomialName    = "monomial/transcript00.dat"
	flatName        = "flat/g1.dat"
	barretenbergRef = "AztecProtocol/aztec-packages barretenberg/sol/src/honk/utils.sol (commit f2f4ecab), G2 point from VK"
)

// [x]_2 of Ignition: x.c0, x.c1, y.c0, y.c1 (manifest.json crs.t2; barretenberg lists it as x.c1, x.c0, y.c1, y.c0).
var pinnedT2 = [4]string{
	"0x0118c4d5b837bcc2bc89b5b398b5974e9f5944073b32078b7e231fec938883b0",
	"0x260e01b251f6f1c7e7ff4e580791dee8ea51d87a358e038b4efe30fac09383c1",
	"0x22febda3c0c0632a56475b4214e5615e11e6dd3f96e6cea2854a87d4dacc5e55",
	"0x04fc6369f7110fe3d25156c1bb9a72859cf2a04641f99ba4ee413c80da6a5fe4",
}

var (
	cacheDir string
	record   = map[string]any{}
	files    []map[string]any
	g1gen    curve.G1Affine
	g2gen    curve.G2Affine
)

func must(err error) {
	if err != nil {
		panic(err)
	}
}

func check(ok bool, what string) {
	if !ok {
		fmt.Fprintln(os.Stderr, "FAIL:", what)
		os.Exit(1)
	}
	fmt.Println("ok  ", what)
}

// fetch returns bytes [start, end] of name (end < 0: whole file), cached under cacheDir/local.
func fetch(name string, start, end int64, local string) []byte {
	path := filepath.Join(cacheDir, local)
	b, err := os.ReadFile(path)
	if err != nil {
		url := baseURL + strings.ReplaceAll(name, " ", "%20")
		req, err := http.NewRequest("GET", url, nil)
		must(err)
		if end >= 0 {
			req.Header.Set("Range", fmt.Sprintf("bytes=%d-%d", start, end))
		}
		var resp *http.Response
		for try := 0; ; try++ {
			resp, err = http.DefaultClient.Do(req)
			if err == nil && (resp.StatusCode == 200 || resp.StatusCode == 206) {
				break
			}
			if resp != nil {
				resp.Body.Close()
			}
			if try == 4 {
				panic(fmt.Sprintf("download %s: %v %v", url, err, resp))
			}
			time.Sleep(time.Second << try)
		}
		b, err = io.ReadAll(resp.Body)
		resp.Body.Close()
		must(err)
		if end >= 0 && (resp.StatusCode != 206 || int64(len(b)) != end-start+1) {
			panic(fmt.Sprintf("range %s %d-%d: status %d, %d bytes", url, start, end, resp.StatusCode, len(b)))
		}
		must(os.MkdirAll(filepath.Dir(path), 0o755))
		must(os.WriteFile(path, b, 0o644))
	}
	if end >= 0 && int64(len(b)) != end-start+1 {
		panic("cached " + path + " has the wrong size")
	}
	return b
}

func sha(b []byte) string { h := sha256.Sum256(b); return hex.EncodeToString(h[:]) }

func addFile(name string, start, end int64, b []byte) {
	files = append(files, map[string]any{"url": baseURL + strings.ReplaceAll(name, " ", "%20"), "range": fmt.Sprintf("%d-%d", start, end), "sha256": sha(b)})
}

// Ignition field element: 4 uint64 words, least significant first, each big-endian.
func ignFp(b []byte) fp.Element {
	v := new(big.Int)
	for i := 3; i >= 0; i-- {
		v.Lsh(v, 64).Or(v, new(big.Int).SetUint64(binary.BigEndian.Uint64(b[8*i:8*i+8])))
	}
	if v.Cmp(fp.Modulus()) >= 0 {
		panic("non-canonical coordinate")
	}
	var e fp.Element
	e.SetBigInt(v)
	return e
}

func ignG1(b []byte) curve.G1Affine {
	p := curve.G1Affine{X: ignFp(b[0:32]), Y: ignFp(b[32:64])}
	if p.IsInfinity() || !p.IsOnCurve() || !p.IsInSubGroup() {
		panic("invalid G1 point")
	}
	return p
}

func ignG2(b []byte) curve.G2Affine {
	var q curve.G2Affine
	q.X.A0, q.X.A1, q.Y.A0, q.Y.A1 = ignFp(b[0:32]), ignFp(b[32:64]), ignFp(b[64:96]), ignFp(b[96:128])
	if q.IsInfinity() || !q.IsOnCurve() || !q.IsInSubGroup() {
		panic("invalid G2 point")
	}
	return q
}

func beG1(b []byte) curve.G1Affine {
	var p curve.G1Affine
	must(p.X.SetBytesCanonical(b[0:32]))
	must(p.Y.SetBytesCanonical(b[32:64]))
	if !p.IsOnCurve() || !p.IsInSubGroup() {
		panic("invalid G1 point (flat)")
	}
	return p
}

func checkHeader(b []byte, what string) {
	u := func(i int) uint32 { return binary.BigEndian.Uint32(b[4*i : 4*i+4]) }
	ok := u(0) == 0 && u(1) == 20 && u(2) == totalG1 && u(3) == 1 && u(4) == pointsPerFile && u(5) == 2 && u(6) == 0
	if !ok {
		panic(what + ": unexpected transcript header " + hex.EncodeToString(b[:28]))
	}
}

// e(a1, a2) == e(b1, b2)
func sameRatio(a1, b1 curve.G1Affine, a2, b2 curve.G2Affine) bool {
	var na2 curve.G2Affine
	na2.Neg(&a2)
	ok, err := curve.PairingCheck([]curve.G1Affine{a1, b1}, []curve.G2Affine{na2, b2})
	must(err)
	return ok
}

func g2Pinned() curve.G2Affine {
	var e [4]fp.Element
	for i, s := range pinnedT2 {
		v, ok := new(big.Int).SetString(s[2:], 16)
		if !ok {
			panic("pinned")
		}
		e[i].SetBigInt(v)
	}
	return curve.G2Affine{X: curve.E2{A0: e[0], A1: e[1]}, Y: curve.E2{A0: e[2], A1: e[3]}}
}

func main() {
	flag.StringVar(&cacheDir, "cache", "srs-cache", "download cache directory")
	logN := flag.Int("log", 16, "largest supported domain: n <= 2^log; the SRS holds 2^log + 3 G1 points")
	out := flag.String("out", "", "SRS output file (default <cache>/ignition_bn254_<points>.srs)")
	flag.Parse()
	if *logN < 1 || *logN > maxLogDomain {
		panic("log out of range")
	}
	N := (1 << *logN) + 3 // [x^0..x^{N-1}]_1
	if N-1 > pointsPerFile {
		panic("only the first transcript file is read; log <= 22")
	}
	_, _, g1gen, g2gen = curve.Generators()
	t0 := time.Now()

	// 1. manifest
	mb := fetch("manifest.json", 0, -1, "manifest.json")
	check(sha(mb) == manifestSHA256, "manifest.json sha256 = "+manifestSHA256)
	files = append(files, map[string]any{"url": baseURL + "manifest.json", "range": "all", "sha256": sha(mb)})
	var man struct {
		Name         string `json:"name"`
		NumG1Points  int    `json:"numG1Points"`
		CompletedAt  string `json:"completedAt"`
		Participants []struct {
			Address  string `json:"address"`
			Position int    `json:"position"`
		} `json:"participants"`
		Crs struct {
			T2 []string `json:"t2"`
		} `json:"crs"`
	}
	must(json.Unmarshal(mb, &man))
	check(man.Name == "MAIN IGNITION" && man.NumG1Points == totalG1 && len(man.Participants) == nParticipants,
		fmt.Sprintf("manifest: %s, %d G1 points, %d participants, completed %s", man.Name, man.NumG1Points, len(man.Participants), man.CompletedAt))
	check(len(man.Crs.T2) == 4 && [4]string(man.Crs.T2) == pinnedT2, "manifest crs.t2 = pinned [x]_2 (= barretenberg's hardcoded G2 point)")
	t2 := g2Pinned()
	check(t2.IsOnCurve() && t2.IsInSubGroup(), "pinned [x]_2 is on the curve and in G2")

	// 2-4. chain of the first power over all contributions, then the seal
	prev := g1gen
	chainHash := sha256.New()
	step := func(name, local string) (curve.G1Affine, curve.G2Affine) {
		h := fetch(name, 0, 91, local+".head")
		g := fetch(name, g2Offset, g2Offset+255, local+".g2")
		chainHash.Write(h)
		chainHash.Write(g)
		checkHeader(h, name)
		x1 := ignG1(h[28:92])
		x2, z2 := ignG2(g[0:128]), ignG2(g[128:256])
		if !sameRatio(x1, g1gen, g2gen, x2) {
			panic(name + ": [x]_1 and [x]_2 disagree")
		}
		if !sameRatio(x1, prev, g2gen, z2) {
			panic(name + ": does not follow the previous contribution")
		}
		prev = x1
		return x1, x2
	}
	for i, p := range man.Participants {
		if p.Position < 1 || p.Position > 999 || !strings.HasPrefix(p.Address, "0x") || len(p.Address) != 42 {
			panic("participant entry")
		}
		dir := fmt.Sprintf("%03d_%s", p.Position, strings.ToLower(p.Address))
		step(dir+"/transcript00.dat", filepath.Join("chain", fmt.Sprintf("%03d", i+1)))
	}
	check(true, fmt.Sprintf("%d participants: each [x_k]_1 matches its [x_k]_2 and follows the previous one via [z_k]_2", nParticipants))
	_, sealX2 := step(sealedName, "chain/sealed")
	check(true, "the sealed transcript follows participant 176 (position "+fmt.Sprint(man.Participants[nParticipants-1].Position)+")")
	check(sealX2.Equal(&t2), "sealed [x]_2 = pinned [x]_2")
	record["chainSha256"] = hex.EncodeToString(chainHash.Sum(nil))
	record["chainNote"] = "sha256 over (bytes 0-91 || bytes 322560028-322560283) of transcript00.dat of the 176 participants in manifest order, then sealed"

	// 6. the powers used
	g1b := fetch(sealedName, 28, 28+int64(N-1)*64-1, fmt.Sprintf("sealed_g1_%d.bin", N-1))
	addFile(sealedName, 28, 28+int64(N-1)*64-1, g1b)
	P := make([]curve.G1Affine, N)
	P[0] = g1gen
	for i := 1; i < N; i++ {
		P[i] = ignG1(g1b[64*(i-1) : 64*i])
	}
	check(true, fmt.Sprintf("%d sealed G1 points decoded, on the curve, in G1", N-1))
	r := make([]fr.Element, N-1)
	for i := range r {
		_, err := r[i].SetRandom()
		must(err)
	}
	var L1, L2 curve.G1Affine
	_, err := L1.MultiExp(P[:N-1], r, ecc.MultiExpConfig{})
	must(err)
	_, err = L2.MultiExp(P[1:], r, ecc.MultiExpConfig{})
	must(err)
	check(sameRatio(L1, L2, t2, g2gen), fmt.Sprintf("powers: e(sum r_i [x^i]_1, [x]_2) = e(sum r_i [x^(i+1)]_1, [1]_2) for i < %d", N-1))
	check(!sameRatio(L1, L2, g2gen, g2gen), "control: the same check with [1]_2 in place of [x]_2 fails")

	// 7. cross-checks against Aztec's repackaged copies
	mono := fetch(monomialName, 0, 28+int64(N)*64-1, fmt.Sprintf("monomial_%d.bin", N))
	addFile(monomialName, 0, 28+int64(N)*64-1, mono)
	flat := fetch(flatName, 0, int64(N)*64-1, fmt.Sprintf("flat_%d.bin", N))
	addFile(flatName, 0, int64(N)*64-1, flat)
	okM, okF := true, true
	for i := 0; i < N; i++ {
		m := curve.G1Affine{X: ignFp(mono[28+64*i:]), Y: ignFp(mono[28+64*i+32:])}
		f := beG1(flat[64*i : 64*i+64])
		okM = okM && m.Equal(&P[i])
		okF = okF && f.Equal(&P[i])
	}
	check(okM, "monomial/transcript00.dat holds the same first points ([1]_1 then the sealed powers)")
	check(okF, "flat/g1.dat (barretenberg's CRS source) holds the same first points")

	// SRS
	srs := kzg.SRS{Pk: kzg.ProvingKey{G1: P}}
	srs.Vk.G1 = g1gen
	srs.Vk.G2 = [2]curve.G2Affine{g2gen, t2}
	srs.Vk.Lines[0] = curve.PrecomputeLines(srs.Vk.G2[0])
	srs.Vk.Lines[1] = curve.PrecomputeLines(srs.Vk.G2[1])
	if *out == "" {
		*out = filepath.Join(cacheDir, fmt.Sprintf("ignition_bn254_%d.srs", N))
	}
	var buf bytes.Buffer
	_, err = srs.WriteTo(&buf)
	must(err)
	must(os.WriteFile(*out, buf.Bytes(), 0o644))
	t2raw := t2.RawBytes()
	record["ceremony"] = "Aztec Ignition, MAIN IGNITION (176 participants, 2019-10-25 to 2019-12-17), sealed"
	record["files"] = files
	record["g1Points"] = N
	record["maxDomainLog2"] = *logN
	record["tau2RawEVM"] = hex.EncodeToString(t2raw[:])
	record["barretenbergRef"] = barretenbergRef
	record["srsFile"] = map[string]any{"format": "gnark-crypto v0.21 kzg.SRS.WriteTo (compressed points)", "bytes": buf.Len(), "sha256": sha(buf.Bytes())}
	rb, err := json.MarshalIndent(record, "", "  ")
	must(err)
	must(os.WriteFile(*out+".json", append(rb, '\n'), 0o644))
	fmt.Printf("SRS: %d G1 points (n <= 2^%d), %d bytes, sha256 %s\n  -> %s (record %s.json), %.1fs\n",
		N, *logN, buf.Len(), sha(buf.Bytes()), *out, *out, time.Since(t0).Seconds())
}
