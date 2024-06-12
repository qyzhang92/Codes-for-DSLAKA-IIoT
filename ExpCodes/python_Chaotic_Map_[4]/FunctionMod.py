import nist256.ecdh as ecdh
import nist256.curve as curve
import nist256.big as big
import nist256.ecp as ecp
import random
from pypuf.simulation import XORArbiterPUF, ArbiterPUF
import numpy as np
import hashlib
import secrets


# Fast Recursion
def T(n, x, p):
    if n == 0:
        return 1
    elif n == 1:
        return x
    elif n % 2 == 0:  # 偶数
        temp = T(n // 2, x, p)
        return (2 * temp * temp - 1) % p
    else:
        if n % 4 == 1:
            odd = (n + 3) // 4
            even = (n - 1) // 4  # 偶数
        else:
            odd = (n - 3) // 4
            even = (n + 1) // 4
        A = T(even, x, p)
        B = T(odd, x, p)
        C = (2 * A * A - 1) % p
        D = (2 * A * B - x) % p
        return (2 * C * D - x) % p

def hash_256(*args):
    str1 = ""
    for arg in args:
        str1 = str1 + str(arg)
    str1 = str1.encode()
    return hashlib.sha3_256(str1).hexdigest()


def hash_512(*args):
    str1 = ""
    for arg in args:
        str1 = str1 + str(arg)
    str1 = str1.encode()
    return hashlib.sha3_512(str1).hexdigest()


def a_mul_p(a, G):
    # s = a % curve.r
    Y = a * G
    return Y


def a_mul_pk(a, W):
    return ecdh.ECP_SvdpDH(a, W)


def hex_string_to_ndarray(hex_string):
    binary_string = bin(int(hex_string, 16))[2:].zfill(256)
    binary_array = np.array(
        [int(bit) * 2 - 1 for bit in binary_string], dtype=np.int8).reshape((32, 8))
    return binary_array


def ndarray_to_hex_string(ndarray):
    # Flatten the ndarray to a 1D array
    flattened_array = ndarray.flatten()

    # Convert -1 to '0' and 1 to '1' in the flattened array
    binary_array = ['1' if x == 1 else '0' for x in flattened_array]

    # Join the binary digits into a single binary string
    binary_string = ''.join(binary_array)

    # Convert the binary string to a hex string
    hex_string = hex(int(binary_string, 2))[2:].upper()

    # Pad the hex string with leading zeros to make it 64 characters (256 bits)
    hex_string = hex_string.zfill(64)

    return hex_string


def expand_hex_string_to_ndarray(hex_string: str):
    m = hashlib.sha256()
    c = hex_string_to_ndarray(hex_string)
    for _ in range(0, 7):
        m.update(hex_string.encode('utf-8'))
        hex_string = m.hexdigest()
        nd = hex_string_to_ndarray(m.hexdigest())
        c = np.concatenate((c, nd), axis=0)
    return c


def get_puf(c: str):
    c = expand_hex_string_to_ndarray(c)
    r = ndarray_to_hex_string(XORArbiterPUF(n=8, k=1, seed=1).eval(c))
    return r


def xor_strings(str1, str2):
    len2 = min(len(str1), len(str2))
    if (len(str1) > len(str2)):
        str3 = str1[:len2]
        result = ''.join(chr(ord(a) ^ ord(b)) for a, b in zip(str3, str2))
        return result + str1[len2:]
    else:
        str3 = str2[:len2]
        result = ''.join(chr(ord(a) ^ ord(b)) for a, b in zip(str1, str3))
        return result + str2[len2:]
