package main

import (
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/hash/mimc"
	"github.com/consensys/gnark/std/rangecheck"
)

// MulCircuit mirrors the shape of the bench's Groth16 fixtures: exactly two public inputs (n0, n1).
//
// The bench's Groth16 fixtures are synthetic: their VK is built from known scalars and each proof is
// solved in the exponent, so they prove no circuit at all (zk-verifier-bench docs/proof-generality.md).
// The closest real statement with the same public interface is a tiny circuit over two public inputs.
// We use the classic "factor + sum" statement: the prover knows a, b with
//
//	a * b == n0   and   a + b == n1.
type MulCircuit struct {
	N0 frontend.Variable `gnark:",public"`
	N1 frontend.Variable `gnark:",public"`
	A  frontend.Variable
	B  frontend.Variable
}

func (c *MulCircuit) Define(api frontend.API) error {
	api.AssertIsEqual(api.Mul(c.A, c.B), c.N0)
	api.AssertIsEqual(api.Add(c.A, c.B), c.N1)
	return nil
}

// MerkleDepth is the depth of the membership tree (2^16 leaves).
const MerkleDepth = 16

// MerkleCircuit is an application-shaped statement a BCH contract would plausibly use: membership of a
// hashed leaf in a Merkle tree with a nullifier (Semaphore / Tornado shape), with MiMC-BN254 (gnark's
// std/hash/mimc, Miyaguchi-Preneel over the x^5 MiMC permutation) as the SNARK-friendly hash.
//
// Public inputs (3):
//
//	Root           the Merkle root a covenant would keep in its state
//	NullifierHash  MiMC(nullifier), recorded on-chain to stop double use
//	Context        an arbitrary field element the proof is bound to (e.g. a hash of the spending
//	               transaction's outputs, reduced mod r), so a proof cannot be replayed elsewhere
//
// Private: nullifier, trapdoor, the sibling path and the index bits. leaf = MiMC(nullifier, trapdoor).
type MerkleCircuit struct {
	Root          frontend.Variable `gnark:",public"`
	NullifierHash frontend.Variable `gnark:",public"`
	Context       frontend.Variable `gnark:",public"`
	Nullifier     frontend.Variable
	Trapdoor      frontend.Variable
	Path          [MerkleDepth]frontend.Variable
	Index         [MerkleDepth]frontend.Variable
}

func (c *MerkleCircuit) Define(api frontend.API) error {
	h, err := mimc.NewMiMC(api)
	if err != nil {
		return err
	}
	h.Write(c.Nullifier)
	api.AssertIsEqual(h.Sum(), c.NullifierHash)

	h.Reset()
	h.Write(c.Nullifier, c.Trapdoor)
	cur := h.Sum()
	for i := 0; i < MerkleDepth; i++ {
		api.AssertIsBoolean(c.Index[i])
		left := api.Select(c.Index[i], c.Path[i], cur)
		right := api.Select(c.Index[i], cur, c.Path[i])
		h.Reset()
		h.Write(left, right)
		cur = h.Sum()
	}
	api.AssertIsEqual(cur, c.Root)

	// Context needs no constraint to be bound: a PLONK public input fixes its wire through the PI(X)
	// term of the gate identity (the tampered-Context vectors check this).
	return nil
}

// MerkleRangeCircuit is merkle16 with a private 64-bit amount in the leaf, checked by gnark's std/rangecheck
// gadget. On the PLONK (scs) builder rangecheck uses the log-derivative lookup argument, which calls
// api.Commit once, so the circuit has exactly one BSB22 commitment (vk.Qcp has length 1).
//
// Public inputs (3): Root, NullifierHash, Context, as in merkle16.
// Private: nullifier, trapdoor, amount, the sibling path and the index bits. leaf = MiMC(nullifier, trapdoor, amount),
// with 0 <= amount < 2^64 (a confidential-note shape: the amount is hidden but bounded).
type MerkleRangeCircuit struct {
	Root          frontend.Variable `gnark:",public"`
	NullifierHash frontend.Variable `gnark:",public"`
	Context       frontend.Variable `gnark:",public"`
	Nullifier     frontend.Variable
	Trapdoor      frontend.Variable
	Amount        frontend.Variable
	Path          [MerkleDepth]frontend.Variable
	Index         [MerkleDepth]frontend.Variable
}

func (c *MerkleRangeCircuit) Define(api frontend.API) error {
	h, err := mimc.NewMiMC(api)
	if err != nil {
		return err
	}
	h.Write(c.Nullifier)
	api.AssertIsEqual(h.Sum(), c.NullifierHash)

	rangecheck.New(api).Check(c.Amount, 64)

	h.Reset()
	h.Write(c.Nullifier, c.Trapdoor, c.Amount)
	cur := h.Sum()
	for i := 0; i < MerkleDepth; i++ {
		api.AssertIsBoolean(c.Index[i])
		left := api.Select(c.Index[i], c.Path[i], cur)
		right := api.Select(c.Index[i], cur, c.Path[i])
		h.Reset()
		h.Write(left, right)
		cur = h.Sum()
	}
	api.AssertIsEqual(cur, c.Root)
	return nil
}

// Range64Circuit is the smallest circuit with one BSB22 commitment: public n0, private a with a*a == n0 and
// 0 <= a < 2^64 (rangecheck gadget). It is a quick debugging target for the commitment path.
type Range64Circuit struct {
	N0 frontend.Variable `gnark:",public"`
	A  frontend.Variable
}

func (c *Range64Circuit) Define(api frontend.API) error {
	api.AssertIsEqual(api.Mul(c.A, c.A), c.N0)
	rangecheck.New(api).Check(c.A, 64)
	return nil
}
