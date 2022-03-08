from pickle import FALSE
import random
import hashlib

rsa = __import__("06_rsa")
rsa_key_gen = __import__("07_rsa_key_gen")

hash = lambda m : int.from_bytes(hashlib.sha1(m).digest(), 'big')

def bitLength(n : int) -> int:
    length = 0
    while n > 0:
        n >>= 1
        length += 1
    return length

def genParameters(L : int = 1024, N : int = 160):
    s = random.randrange(2**(N-1) // 30, (2**N - 1) // 30)
    q = rsa_key_gen.getNextPrime(s * 30)

    if bitLength(q) != N:
        return genParameters(L, N)

    # start value for k
    k = (2**(L-1)) // q
    while not rsa_key_gen.checkPrime(p := k*q+1):
        if bitLength(p) > L:
            return genParameters(L, N)
        k += 1
    
    while True:
        h = random.randrange(2, p-2)
        g = rsa.powWithMod(h, k, p)
        if g != 1:
            return p, q, g

def genKey(p : int, q : int, g : int):
    x = random.randrange(2, q-2)
    return x, rsa.powWithMod(g, x, p)

def sign(hashedM : int, p : int, q : int, g : int, x : int):
    j = random.randrange(2, q-1)
    r = rsa.powWithMod(g, j, p) % q

    if r == 0:
        return sign(hashedM, p, q, g, x)
    
    s = (rsa.mudularInverse(j, q) * (hashedM + r * x)) % q

    if s == 0:
        return sign(hashedM, p, q, g, x)
    
    return r, s

def verify(signatur : tuple[int], hashedM : int, p : int, q : int, g : int, y : int):
    (r, s) = signatur

    if not (0 < r < q and 0 < s < q):
        return False
    
    w = rsa.mudularInverse(s, q)
    u1 = (hashedM * w) % q
    u2 = (r * w) % q
    v = ((rsa.powWithMod(g, u1, p) * rsa.powWithMod(y, u2, p)) % p) % q

    return v == r

if __name__ == "__main__":
    p, q, g = genParameters()
    x, y    = genKey(p, q, g)
    m = bytearray([2, 3, 4])
    hashedM = hash(m)


    signatur = sign(hashedM, p, q, g, x)

    print(verify(signatur, hashedM, p, q, g, y))

    hashedM += 1
    print(verify(signatur, hashedM, p, q, g, y))

