# chunked/ — BCH-limit-viable multi-transaction verifiers

Each verifier step here is split across multiple contracts/transactions so that EVERY chunk fits one BCH input (locking+unlocking <= 10,000 bytes, op-cost <= 8,032,800). State (Jacobian accumulator + base point + counter + inputs) is carried between chunks via a `hash256` commitment (see ../multi-step-computation.md). Each chunk's result must match the singleton reference at the corresponding iteration boundary.
