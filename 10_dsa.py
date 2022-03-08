from pickle import FALSE
import random
import hashlib

rsa = __import__("06_rsa")
rsa_key_gen = __import__("07_rsa_key_gen")
sha1 = __import__("11_sha1")

hash = lambda m : sha1.sha1(m)

def bitLength(n : int) -> int:
    """
    Calculates the number of bits of a number.

    Args:
        n (int): The number the number of bits should be evaluated. 

    Returns:
        int: The number of bits.
    """
    length = 0
    while n > 0:
        n >>= 1
        length += 1
    return length

def genParameters(L : int = 1024, N : int = 160) -> tuple[int]:
    """
    Generates all global parameters used in the DSA
    - q is prime of bit length L
    - p is prime of bit length N and p = k*q+1 for some natural k
    - g is element in Z*_p with order q

    Args:
        L (int, optional): Length of q. Defaults to 1024.
        N (int, optional): Length of p. Defaults to 160.

    Returns:
        tuple[int]: q, p, g
    """
    s = random.randrange(2**(N-1) // 30, (2**N - 1) // 30)
    q = rsa_key_gen.getNextPrime(s * 30)

    # find p, q. If it fails, recursively recall this method
    if bitLength(q) != N:
        return genParameters(L, N)

    # start value for k
    k = (2**(L-1)) // q
    while not rsa_key_gen.checkPrime(p := k*q+1):
        if bitLength(p) > L:
            return genParameters(L, N)
        k += 1
    
    # find g.
    # g = h^((p-1)/q) mod p for a random 1 < h < p-1.
    # g shouldn't be 1
    while True:
        h = random.randrange(2, p-2)
        g = rsa.powWithMod(h, k, p)
        if g != 1:
            return p, q, g

def genKey(p : int, q : int, g : int) -> tuple[int]:
    """
    Generate public and private key given public parameters.

    Args:
        p (int): Prime p
        q (int): Prime q
        g (int): Generator g

    Returns:
        tuple[int]: secret key, public key
    """
    x = random.randrange(2, q-2)
    return x, rsa.powWithMod(g, x, p)

def sign(hashedM : int, p : int, q : int, g : int, x : int) -> tuple[int]:
    """
    Signes a method using the hashed message, private key and public parameters.

    Args:
        hashedM (int): Hashed message.
        p (int): Public parameter prime p
        q (int): Public parameter prime q
        g (int): Public parameter generator g
        x (int): Secret key.

    Returns:
        tuple[int]: signiture
    """
    j = random.randrange(2, q-1)
    r = rsa.powWithMod(g, j, p) % q

    if r == 0:
        return sign(hashedM, p, q, g, x)
    
    s = (rsa.mudularInverse(j, q) * (hashedM + r * x)) % q

    if s == 0:
        return sign(hashedM, p, q, g, x)
    
    return r, s

def verify(signatur : tuple[int], hashedM : int, p : int, q : int, g : int, y : int) -> bool:
    """
    Verifies a signature given the signiture, hashed message, public key of the person who signed and public parameters.

    Args:
        signatur (tuple[int]): signature
        hashedM (int): hashed message
        p (int): Public parameter prime p
        q (int): Public parameter prime q
        g (int): Public parameter generator g
        x (int): Public key of the person who signed.

    Returns:
        bool: Whther the verification succeeded.
    """
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

    print(verify(signatur, hashedM+1, p, q, g, y))

    print(verify((signatur[0]-1, signatur[1]+1), hashedM+1, p, q, g, y))

