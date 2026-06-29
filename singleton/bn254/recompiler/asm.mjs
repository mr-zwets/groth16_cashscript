// Minimal BCH script (dis)assembler over raw bytes, with recursive descent into
// pushed "subroutine body" blobs (the OP_DEFINE operands in the cashc fork).
//
// parse(bytes) -> array of ops: {op, hdr, data?, off}
//   op   = opcode byte
//   hdr  = header length (1 for opcode or single-byte push, 2/3/5 for PUSHDATA)
//   data = Uint8Array payload for pushes (undefined for plain opcodes)
//   off  = byte offset in the input
//
// serialize(ops) -> Uint8Array  (re-encodes, choosing the minimal push header)

export function parse(bytes) {
  const ops = [];
  let i = 0;
  while (i < bytes.length) {
    const op = bytes[i];
    let hdr = 1, dataLen = 0;
    if (op >= 1 && op <= 75) { dataLen = op; hdr = 1; }
    else if (op === 76) { dataLen = bytes[i + 1]; hdr = 2; }
    else if (op === 77) { dataLen = bytes[i + 1] | (bytes[i + 2] << 8); hdr = 3; }
    else if (op === 78) { dataLen = bytes[i + 1] | (bytes[i + 2] << 8) | (bytes[i + 3] << 16) | (bytes[i + 4] << 24); hdr = 5; }
    if (dataLen > 0 || (op >= 1 && op <= 78 && op !== 0)) {
      if (op >= 1 && op <= 78) {
        const data = bytes.slice(i + hdr, i + hdr + dataLen);
        ops.push({ op, hdr, data, off: i });
        i += hdr + dataLen;
        continue;
      }
    }
    ops.push({ op, hdr: 1, off: i });
    i += 1;
  }
  return ops;
}

// minimal push header for a payload of length n
function pushHeader(n) {
  if (n <= 75) return Uint8Array.from([n]);
  if (n <= 255) return Uint8Array.from([76, n]);
  if (n <= 65535) return Uint8Array.from([77, n & 0xff, (n >> 8) & 0xff]);
  return Uint8Array.from([78, n & 0xff, (n >> 8) & 0xff, (n >> 16) & 0xff, (n >> 24) & 0xff]);
}

export function serialize(ops) {
  const chunks = [];
  for (const o of ops) {
    if (o.data !== undefined) {
      chunks.push(pushHeader(o.data.length));
      chunks.push(o.data);
    } else {
      chunks.push(Uint8Array.from([o.op]));
    }
  }
  let len = 0; for (const c of chunks) len += c.length;
  const out = new Uint8Array(len);
  let p = 0; for (const c of chunks) { out.set(c, p); p += c.length; }
  return out;
}

// Heuristic: is this push a subroutine body (vs a numeric/constant operand)?
// In this build, DEFINE bodies are the larger blobs of executable script.
// We treat a push as a body if it is immediately followed by a small int + OP_DEFINE,
// but simplest: caller decides. Here we expose a guess used for analysis only.
export function looksLikeBody(data) {
  if (!data || data.length < 4) return false;
  // bodies are dense in stack ops; constants (field elements) are 32 bytes of entropy.
  if (data.length === 32 || data.length === 24 || data.length === 35) return false;
  return true;
}
