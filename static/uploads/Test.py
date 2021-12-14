import os
import socket
import sys
from termcolor import colored
from threading import Thread
import time
import socket, sys, threading, time, random, winsound, os
import hashlib as hasher
from hashlib import sha256
from datetime import datetime
from time import strftime
from six.moves import xrange
from math import log
import operator
import numpy,csv,json
import hashlib
import string
import collections
import struct
import binascii
import base64, base58
from copy import copy
from fractions import gcd # Greatest Common Denominator
from random import SystemRandom # cryptographic random byte generator
rand=SystemRandom()
from numpy import asarray
from numpy import save
from numpy import load
from binascii import hexlify, unhexlify

os.system('color A')
# Convert a string with hex digits, colons, and whitespace to a long integer
# Convert a string with hex digits, colons, and whitespace to a long integer
def hex2int(hexString):
	return int("".join(hexString.replace(":","").split()),16)

# Useful for very coarse version differentiation.
PY3 = sys.version_info[0] == 3

if PY3:
    indexbytes = operator.getitem
    intlist2bytes = bytes
    int2byte = operator.methodcaller("to_bytes", 1, "big")
else:
    int2byte = chr
    range = xrange

    def indexbytes(buf, i):
        return ord(buf[i])

    def intlist2bytes(l):
        return b"".join(chr(c) for c in l)


b = 256
p = 2 ** 255 - 19
l = 2 ** 252 + 27742317777372353535851937790883648493


def H(m):
    return hashlib.sha512(m).digest()

def pow2(x, q):
    """== pow(x, 2**p, q)"""
    while q > 0:
        x = x * x % p
        q -= 1
    return x
def sha512_modq(s):
    return int.from_bytes(H(s), "little") % l

def half_extended_gcd(aa, bb):
	lastrem, rem = abs(aa), abs(bb)
	x, lastx = 0, 1
	while rem:
		lastrem, (quotient, rem) = rem, divmod(lastrem, rem)
		x, lastx = lastx - quotient*x, x
	return lastrem, lastx

# Modular inverse: compute the multiplicative inverse i of a mod m:
#     i*a = a*i = 1 mod m
def modular_inverse(a):
	g, x = half_extended_gcd(a, p)
	if g != 1:
		raise ValueError
	return x % p

# def modp_inv(x):
     # return pow(x, q-2, q)

d = -121665 * modular_inverse(121666) % p
I = pow(2, (p - 1) // 4, p)


def xrecover(y):
    xx = (y * y - 1) * modular_inverse(d * y * y + 1)
    x = pow(xx, (p + 3) // 8, p)

    if (x * x - xx) % p != 0:
        x = (x * I) % p

    if x % 2 != 0:
        x = p-x

    return x


Gy = 4 * modular_inverse(5)
Gx = xrecover(Gy)
G = (Gx % p, Gy % p, 1, (Gx * Gy) % p)
ident = (0, 1, 1, 0)

def point_add(P, Q):
    # This is formula sequence 'addition-add-2008-hwcd-3' from
    # http://www.hyperelliptic.org/EFD/g1p/auto-twisted-extended-1.html
    (X1, Y1, Z1, T1) = P
    (X2, Y2, Z2, T2) = Q

    A = (Y1-X1)*(Y2-X2) % p
    B = (Y1+X1)*(Y2+X2) % p
    C = T1*2*d*T2 % p
    DD = Z1*2*Z2 % p
    E = B - A
    F = DD - C
    G = DD + C
    H = B + A
    X3 = E*F
    Y3 = G*H
    T3 = E*H
    Z3 = F*G

    return(X3 % p, Y3 % p, Z3 % p, T3 % p)


def point_double(P):
    # This is formula sequence 'dbl-2008-hwcd' from
    # http://www.hyperelliptic.org/EFD/g1p/auto-twisted-extended-1.html
    (X1, Y1, Z1, T1) = P

    A = X1*X1 % p
    B = Y1*Y1 % p
    C = 2*Z1*Z1 % p
    # DD = -A
    E = ((X1+Y1)*(X1+Y1) - A - B) % p
    G = -A + B  # DD + B
    F = G - C
    H = -A - B  # DD - B
    X3 = E*F
    Y3 = G*H
    T3 = E*H
    Z3 = F*G

    return (X3 % p, Y3 % p, Z3 % p, T3 % p)


def point_mult(k,P):
    if k == 0:
        return ident
    Q = point_mult( k // 2, P)
    Q = point_double(Q)
    if k & 1:
        Q = point_add(Q, P)
    return Q


# Gpow[i] == point_mult(G, 2**i)
Gpow = []


def make_Gpow():
    P = G
    for i in range(253):
        Gpow.append(P)
        P = point_double(P)
make_Gpow()


def point_mult_G(k):
    """
    Implements point_mult(k,G) more efficiently.
    """
    # point_mult(l,G) is the identity
    k = k % l
    P = ident
    for i in range(253):
        if k & 1:
            P = point_add(P, Gpow[i])
        k = k // 2
    assert k == 0, k
    return P




# def encodepoint(P):
    # (x, y, z, t) = P
    # zi = modular_inverse(z)
    # x = (x * zi) % q
    # y = (y * zi) % q
    # bits = [(y >> i) & 1 for i in range(b - 1)] + [x & 1]
    # return b''.join([
        # int2byte(sum([bits[i * 8 + j] << j for j in range(8)]))
        # for i in range(b // 8)
    # ])






def secret_expand(secret):
    if len(secret) != 32:
        raise Exception("Bad size of private key")
    h = H(secret)
    a = int.from_bytes(h[:32], "little")
    a &= (1 << 254) - 8
    a |= (1 << 254)
    b= h[32:]
    return (a, b)

def secret_to_public(secret):
    (a, dummy) = secret_expand(secret)
    return encodepoint(point_mult_G(a))


def Hint(m):
    h = H(m)
    return sum(2 ** i * bit(h, i) for i in range(2 * b))


# def sign(m, sk, pk):
    # """
    # Not safe to use with secret keys or secret data.

    # See module docstring.  This function should be used for testing only.
    # """
    # h = H(sk)
    # a = 2 ** (b - 2) + sum(2 ** i * bit(h, i) for i in range(3, b - 2))
    # r = Hint(
        # intlist2bytes([indexbytes(h, j) for j in range(b // 8, b // 4)]) + m
    # )
    # R = point_mult_G(r)
    # S = (r + Hint(encodepoint(R) + pk + m) * a) % l
    # return encodepoint(R) + encodeint(S)


def isoncurve(P):
    (x, y, z, t) = P
    return (z % p != 0 and
            x*y % p == z*t % p and
            (y*y - x*x - z*z - d*t*t) % p == 0)
def point_equal(P, Q):
    # x1 / z1 == x2 / z2  <==>  x1 * z2 == x2 * z1
    if (P[0] * Q[2] - Q[0] * P[2]) % p != 0:
        return False
    if (P[1] * Q[2] - Q[1] * P[2]) % p != 0:
        return False
    return True

def bit(h, i):
    return (indexbytes(h, i // 8) >> (i % 8)) & 1

def encodeint(y):
    bits = [(y >> i) & 1 for i in range(b)]
    return b''.join([
        int2byte(sum([bits[i * 8 + j] << j for j in range(8)]))
        for i in range(b//8)
    ])

def encodepoint(P): #point to bytes (point compress)
    zinv = modular_inverse(P[2])
    x = P[0] * zinv % p
    y = P[1] * zinv % p
    return int.to_bytes(y | ((x & 1) << 255), 32, "little")




def decodeint(s):
    return sum(2 ** i * bit(s, i) for i in range(0, b))


def decodepoint(s): #bytes to point (point decompress)
    y = sum(2 ** i * bit(s, i) for i in range(0, b - 1))
    x = xrecover(y)
    if x & 1 != bit(s, b-1):
        x = p - x
    P = (x, y, 1, (x*y) % p)

    if not isoncurve(P):
        raise ValueError("decoding point that is not on curve")
    return P



def sign(secret, msg):
    a, prefix = secret_expand(secret)
    A = encodepoint(point_mult_G(a))
    T=msg.encode()
    r = sha512_modq(prefix + T)
    R = point_mult_G(r)
    Rs = encodepoint(R)
    h = sha512_modq(Rs + A + T)
    s = (r + h * a) % l
    return Rs + int.to_bytes(s, 32, "little")

## And finally the verification function.

def verify(public, msg, signature):
    if len(public) != 32:
        raise Exception("Bad public key length")
    if len(signature) != 64:
        Exception("Bad signature length")
    A = decodepoint(public)
    if not A:
        return False
    Rs = signature[:32]
    R = decodepoint(Rs)
    if not R:
        return False
    s = int.from_bytes(signature[32:], "little")
    if s >= l: return False
    T=msg.encode()
    h = sha512_modq(Rs + public + T)
    sB = point_mult_G(s)
    hA = point_mult(h,A)
    return point_equal(sB, point_add(R, hA))


def b58encode(data):
    B58 = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"

    if data[0] == 0:
        return "1" + b58(data[1:])

    x = sum([v * (256 ** i) for i, v in enumerate(data[::-1])])
    ret = ""
    while x > 0:
        ret = B58[x % 58] + ret
        x = x // 58

    return ret

def b58decode(s):
    """Decode a base58-encoding string, returning bytes"""
    b58_digits = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz'
    if not s:
        return b''

    # Convert the string to an integer
    n = 0
    for c in s:
        n *= 58
        if c not in b58_digits:
            raise InvalidBase58Error('Character %r is not a valid base58 character' % c)
        digit = b58_digits.index(c)
        n += digit

    # Convert the integer to bytes
    h = '%x' % n
    if len(h) % 2:
        h = '0' + h
    res = unhexlify(h.encode('utf8'))

    # Add padding back.
    pad = 0
    for c in s[:-1]:
        if c == b58_digits[0]: pad += 1
        else: break
    return b'\x00' * pad + res
  
    
student_privkey="8bbf83cfad6bf96bfc20c8b908a946e8c7484cedd0312c9ca78c3f4114864ff2"
student_pubkey="5hcZuqdn7qbXgfpExPmqYGuUaTPYTwcJgR19YA3VWgB"
issuer_privkey="6a93a0b995f20e7727f3e75a5a4e9a1233fecd3011b2627d0a77960d280230b6"
issuer_pubkey="9GjZY6FhBjVCXLgVaBcyAbcJ7dhu31XaxKUrvoM9A7C7"


with open('did_schema_v0.2.json', 'r') as file:

    data = json.load(file)
student_signature=data['authentication']['signatureValue']
issuer_signature=data['proof']['signatureValue']



authentication=verify(b58decode(student_pubkey),str(data['claim']),b58decode(student_signature))
verification=verify(b58decode(issuer_pubkey),str(data['@context'])+str(data['id'])+str(data['type'])+str(data['issuer'])+str(data['issuanceDate'])+str(data['publicKey'])+str(data['claim'])+str(data['authentication']),b58decode(issuer_signature))

print("\nStudent publicKey: ",student_pubkey)
print("Student signature: ",student_signature)
print("Authentication: ",authentication)
print("\nIssuer publicKey: ",issuer_pubkey)
print("Issuer Signature: ",issuer_signature)
print("Verification: ",verification)

