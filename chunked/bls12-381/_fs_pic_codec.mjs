const assert = (condition, message) => {
  if (!condition) throw new Error(message);
};
const concat = (...parts) => {
  const result = new Uint8Array(parts.reduce((size, part) => size + part.length, 0));
  let offset = 0;
  for (const part of parts) { result.set(part, offset); offset += part.length; }
  return result;
};

// Omitted factors are reconstructed before authentication and transcript hashing.
// A nonzero factor at a zero index is retained as an explicitly noncanonical
// record: the decoder rejects its extra bytes, preserving negative-test origins.
export function compactZeroPic(wire, { prefixLength, factorBytes, pathBytes,
  scalar0, scalar1, firstWindow }) {
  assert(scalar0.length === 32 && scalar1.length === 32, 'PIC scalars must be 32 bytes');
  assert(Number.isInteger(firstWindow) && firstWindow >= 0 && firstWindow < 31,
    'PIC window pair is outside the scalar');
  assert(Number.isInteger(prefixLength) && prefixLength >= 0, 'invalid PIC prefix length');
  const recordBytes = factorBytes + pathBytes;
  assert(wire.length === prefixLength + 2 * recordBytes, 'expected two complete legacy PIC records');
  const records = [0, 1].map(slot => {
    const start = prefixLength + slot * recordBytes;
    const record = wire.slice(start, start + recordBytes);
    const window = firstWindow + slot;
    const zeroIndex = scalar0[window] === 0 && scalar1[window] === 0;
    return zeroIndex && record.slice(0, factorBytes).every(byte => byte === 0)
      ? record.slice(factorBytes) : record;
  });
  return concat(wire.slice(0, prefixLength), ...records);
}

export function zeroPicSource(factorBytes, pathBytes) {
  assert(Number.isInteger(factorBytes) && factorBytes > 0 &&
    Number.isInteger(pathBytes) && pathBytes > 0, 'invalid PIC field widths');
  return `function expandZeroPic(bytes wire,int prefixLength,bytes scalar0,bytes scalar1,int firstWindow) returns (bytes) {
    bytes result=wire.split(prefixLength)[0];
    bytes rest=wire.split(prefixLength)[1];
    for (int slot=0;slot<2;slot=slot+1) {
        int window=firstWindow+slot;
        bytes digit=scalar0.split(window+1)[0].split(window)[1]
            +scalar1.split(window+1)[0].split(window)[1];
        if (digit==0x0000) {
            result=result+toPaddedBytes(0,${factorBytes})+rest.split(${pathBytes})[0];
            rest=rest.split(${pathBytes})[1];
        } else {
            result=result+rest.split(${factorBytes + pathBytes})[0];
            rest=rest.split(${factorBytes + pathBytes})[1];
        }
    }
    require(rest.length==0);
    return result;
}
`;
}
