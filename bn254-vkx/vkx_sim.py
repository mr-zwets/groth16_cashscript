"""Port the EXACT vkx.cash algorithm to Python and compare against py_ecc."""
from py_ecc.bn128 import G1, multiply, add, field_modulus

p = field_modulus

def addFp(x, y): return (x + y) % p
def subFp(x, y): return (x - y + p) % p
def mulFp(x, y): return (x * y) % p
def sqrFp(x): return (x * x) % p

def jac_double(X, Y, Z):
    # dbl-2009-l
    a = sqrFp(X)
    b = sqrFp(Y)
    c = sqrFp(b)
    d = mulFp(2, subFp(subFp(sqrFp(addFp(X, b)), a), c))
    e = mulFp(3, a)
    f = sqrFp(e)
    nx = subFp(f, mulFp(2, d))
    ny = subFp(mulFp(e, subFp(d, nx)), mulFp(8, c))
    nz = mulFp(2, mulFp(Y, Z))
    return nx, ny, nz

def jac_add(aX, aY, aZ, bX, bY, bZ):
    # mirror contract: returns (X,Y,Z); assumes neither is infinity (Z!=0)
    z1z1 = sqrFp(aZ)
    z2z2 = sqrFp(bZ)
    u1 = mulFp(aX, z2z2)
    u2 = mulFp(bX, z1z1)
    s1 = mulFp(mulFp(aY, bZ), z2z2)
    s2 = mulFp(mulFp(bY, aZ), z1z1)
    if u1 == u2 and s1 == s2:
        return jac_double(aX, aY, aZ)
    h = subFp(u2, u1)
    i2 = sqrFp(mulFp(2, h))
    j = mulFp(h, i2)
    rr = mulFp(2, subFp(s2, s1))
    v = mulFp(u1, i2)
    nx = subFp(subFp(sqrFp(rr), j), mulFp(2, v))
    ny = subFp(mulFp(rr, subFp(v, nx)), mulFp(2, mulFp(s1, j)))
    nz = mulFp(mulFp(subFp(subFp(sqrFp(addFp(aZ, bZ)), z1z1), z2z2), h), 1)
    return nx, ny, nz

def scalar_mult_acc(accX, accY, accZ, baseX, baseY, k):
    rX, rY, rZ = 0, 1, 0
    bX, bY, bZ = baseX, baseY, 1
    for i in range(254):
        if (k >> i) & 1 == 1:
            if rZ == 0:
                rX, rY, rZ = bX, bY, bZ
            else:
                rX, rY, rZ = jac_add(rX, rY, rZ, bX, bY, bZ)
        if bZ != 0 and bY != 0:
            bX, bY, bZ = jac_double(bX, bY, bZ)
    # acc = acc + R
    if rZ != 0:
        accX, accY, accZ = jac_add(accX, accY, accZ, rX, rY, rZ)
    return accX, accY, accZ

import json, os
_HERE = os.path.dirname(os.path.abspath(__file__))
v = json.load(open(os.path.join(_HERE, 'vkx_vectors.json')))
ic0 = v['ic0']; ic1 = v['ic1']; ic2 = v['ic2']
input0 = v['input0']; input1 = v['input1']

accX, accY, accZ = ic0[0], ic0[1], 1
accX, accY, accZ = scalar_mult_acc(accX, accY, accZ, ic1[0], ic1[1], input0)
accX, accY, accZ = scalar_mult_acc(accX, accY, accZ, ic2[0], ic2[1], input1)

zInv = pow(accZ, p - 2, p)
zInv2 = sqrFp(zInv)
zInv3 = mulFp(zInv2, zInv)
affX = mulFp(accX, zInv2)
affY = mulFp(accY, zInv3)

print("contract affX:", affX)
print("contract affY:", affY)
print("expected affX:", v['expected'][0])
print("expected affY:", v['expected'][1])
print("MATCH:", affX == v['expected'][0] and affY == v['expected'][1])
