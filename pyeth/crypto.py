# -*- coding: utf8 -*-
import binascii
import struct
import sha3
from secp256k1 import ffi, EC_UNCOMPRESSED, lib


# 以太坊使用keccak-256哈希算法
def keccak256(s):
    k = sha3.keccak_256()
    k.update(s)
    return k.digest()


def int_to_big_endian(large_num):
    """
    :param large_num: int | long
    :return: byte string (str)
    """
    if large_num == 0:
        return b'\x00'

    s = hex(large_num)  # got hex string of number: '0x499602d2'
    s = s[2:]  # remove prefix '0x': '499602d2'
    s = s.rstrip('L')  # remove postfix of long number 'L': '499602d2'
    if len(s) & 1:  # if the string length is odd, align to even by add prefix '0': '499602d2'
        s = '0' + s

    s = binascii.a2b_hex(s)  # convert ascii string to byte string

    return s


def big_endian_to_int(value):
    """
    :param value: byte string (str) | byte array
    :return: int | long
    """
    # value can be
    if len(value) == 1:  # 1 byte
        return ord(value)
    elif len(value) <= 8:
        # small than 8 bytes, right align to the 8 bytes window and fill b'\x00' to left empty bytes
        return struct.unpack('>Q', value.rjust(8, b'\x00'))[0]  # got unsigned long long
    else:
        return int(encode_hex(value), 16)


def encode_hex(s):
    """
    :param s: byte array | byte string (str) | unicode
    :return: hex string
    """
    if isinstance(s, bytearray):  # convert byte array to byte string
        s = str(s)

    assert isinstance(s, (str, unicode))
    return s.encode('hex')  # byte string to hex string


def is_on_curve(x, y):
    # https://github.com/ethereum/go-ethereum/blob/master/crypto/secp256k1/curve.go
    # y² = x³ + b
    P = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F
    B = 0x0000000000000000000000000000000000000000000000000000000000000007
    left = y ** 2 % P
    right = (x ** 3 + B) % P

    return left == right


def pubkey_format(pub):
    assert pub.public_key, "No public key defined"

    len_compressed = 65
    res_compressed = ffi.new('unsigned char [%d]' % len_compressed)

    serialized = lib.secp256k1_ec_pubkey_serialize(
        pub.ctx, res_compressed, ffi.new('size_t *', len_compressed), pub.public_key, EC_UNCOMPRESSED)
    assert serialized == 1

    return bytes(ffi.buffer(res_compressed, len_compressed))
