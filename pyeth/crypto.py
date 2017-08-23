# -*- coding: utf8 -*-
import hashlib
import sha3


# 以太坊使用keccak-256哈希算法
def keccak256(s):
    k = sha3.keccak_256()
    k.update(s)
    return k.digest()
