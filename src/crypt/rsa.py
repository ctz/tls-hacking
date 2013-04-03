import random, math, hashlib

small_primes = (
    3, 5, 7, 11, 13, 17, 19, 23, 29,
    31, 37, 41, 43, 47, 53, 59, 61, 67, 71,
    73, 79, 83, 89, 97, 101, 103, 107, 109, 113,
    127, 131, 137, 139, 149, 151, 157, 163, 167, 173,
    179, 181, 191, 193, 197, 199, 211, 223, 227, 229,
    233, 239, 241, 251, 257, 263, 269, 271, 277, 281,
    283, 293, 307, 311, 313, 317, 331, 337, 347, 349,
    353, 359, 367, 373, 379, 383, 389, 397, 401, 409,
    419, 421, 431, 433, 439, 443, 449, 457, 461, 463,
    467, 479, 487, 491, 499, 503, 509, 521, 523, 541,
    547, 557, 563, 569, 571, 577, 587, 593, 599, 601,
    607, 613, 617, 619, 631, 641, 643, 647, 653, 659,
    661, 673, 677, 683, 691, 701, 709, 719, 727, 733,
    739, 743, 751, 757, 761, 769, 773, 787, 797, 809,
    811, 821, 823, 827, 829, 839, 853, 857, 859, 863,
    877, 881, 883, 887, 907, 911, 919, 929, 937, 941,
    947, 953, 967, 971, 977, 983, 991, 997, 1009, 1013,
    1019, 1021, 1031, 1033, 1039, 1049, 1051, 1061, 1063, 1069,
    1087, 1091, 1093, 1097, 1103, 1109, 1117, 1123, 1129, 1151,
    1153, 1163, 1171, 1181, 1187, 1193, 1201, 1213, 1217, 1223,
    1229, 1231, 1237, 1249, 1259, 1277, 1279, 1283, 1289, 1291
)

fpt_trials = 100

def bit_len(x):
    return int(math.ceil(math.log(x, 2)))

def byte_len(x):
    return (bit_len(x) + 7) // 8
    
def modexp(n, e, p):
    return pow(n, e, p)

def perhaps_prime(x):
    # trial division
    for p in small_primes:
        if (x % p) == 0:
            return False
    return True

def probably_prime(x):
    # fermat's little theorem
    for i in range(fpt_trials):
        witness = random.randrange(1, x - 1)
        w = modexp(witness, x - 1, x)
        if w == 1:
            continue
        else:
            return False
    return True

def extended_euclidian(a, b):
    if b == 0:
        return (a, 1, 0)
    assert a > 0 and b > 0

    k = abs(a % b)
    n = a // b
    d, k, l = extended_euclidian(b, k)

    return (d, l, k - l * n)
    
def gen_prime(x):
    while 1:
        candidate = random.getrandbits(x)
        candidate |= 1
        candidate |= 1 << (x - 1)
        assert bit_len(candidate) == x
        if perhaps_prime(candidate) and probably_prime(candidate):
            return candidate

def gen_rsa(x):
    e = 65537
    assert x & 1 == 0
    
    d = -1
    while d < 0:
        n = 1
        while bit_len(n) != x:
            p = gen_prime(x // 2)
            q = gen_prime(x - bit_len(p))
            n = p * q
        
        phi = (p - 1) * (q - 1)
        k, d, _ = extended_euclidian(e, phi)
        assert k == 1
        assert (e * d) % phi == 1
        
    return (e, n), (d, n)

def raw_encrypt(pub, m):
    e, n = pub
    return modexp(m, e, n)

def raw_decrypt(priv, m):
    d, n = priv
    return modexp(m, d, n)

def byteshex(b):
    return ''.join('%02x' % x for x in b)

def int2bytes(m):
    r = []
    for x in range(byte_len(m), 0, -1):
        offs = (x - 1) * 8
        b = (m >> offs) & 0xff
        r.append(b)
    return r

def bytes2int(m):
    return int.from_bytes(bytes(m), byteorder = 'big')

def pkcs1_padding(message, type, getpad, modulus):
    mrl = byte_len(modulus)
    msgl = byte_len(message)

    mr = [0x00, type]
    for _ in range(mrl - 3 - msgl):
        mr.append(getpad())
    mr.append(0x00)
    mr.extend(int2bytes(message))

    return bytes2int(mr)

def pkcs1_unpad(mr, type, modbytes):
    broken = random.getrandbits(modbytes * 8)
    mr = int2bytes(mr)

    if mr[0] != type:
        return broken
    for i in range(1, len(mr)):
        if mr[i] == 0x00:
            return bytes2int(mr[i + 1:])
    return broken

def pkcs1_sign_padding(message, hashf):
    hash = hashf(message).digest()
    hash = bytes2int(hash)
    return pkcs1_padding(hash, 0x01, lambda: 0xff, priv[1])

def pkcs1_verify_padding(modlen, mr, message, hashf):
    hash = hashf(message).digest()
    hash = bytes2int(hash)
    
    if pkcs1_unpad(mr, 0x01, modlen) == hash:
        return
    else:
        raise ValueError('Signature invalid')

def pkcs1_cipher_padding(message, modulus):
    return pkcs1_padding(message, 0x02, lambda: random.randrange(1, 255), modulus)

def pkcs1_cipher_unpad(mr, modulus):
    return pkcs1_unpad(mr, 0x02, byte_len(modulus))

def sign(priv, message, hashf):
    return raw_decrypt(priv, pkcs1_sign_padding(message, hashf))

def verify(pub, message, sig, hashf):
    e, n = pub
    modlen = byte_len(n)
    
    mr = raw_encrypt(pub, sig)
    pkcs1_verify_padding(modlen, mr, message, hashf)

def pkcs1_encrypt(pub, m):
    _, n = pub
    return raw_encrypt(pub, pkcs1_cipher_padding(m, n))

def pkcs1_decrypt(priv, c):
    _, n = priv
    mr = raw_decrypt(priv, c)
    return pkcs1_cipher_unpad(mr, n)

if __name__ == '__main__':
    pub, priv = gen_rsa(1024)
    
    for x in range(10):
        m = random.randrange(1, pub[1] - 1)
        c = raw_encrypt(pub, m)
    
    assert m == raw_decrypt(priv, c)

    m = 123456
    c = pkcs1_encrypt(pub, m)
    assert m == pkcs1_decrypt(priv, c)
    
    sig = sign(priv, 'hello'.encode(), hashlib.sha256)
    verify(pub, 'hello'.encode(), sig, hashlib.sha256)
