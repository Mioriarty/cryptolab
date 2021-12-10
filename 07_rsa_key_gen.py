import random

rsa = __import__("06_rsa")

def doMillerRabin(n : int) -> bool:
    # calculate m and k
    m = n - 1
    k = 0
    while m & 1 == 0 and m > 1:
        k += 1
        m >>= 1

    # choose a
    a = random.randrange(1, n)
    b = rsa.powWithMod(a, m, n)

    if b == 1:
        return True

    # check all powers
    for _ in range(k):
        if b == n-1:
            return True
        else:
            b = (b * b) % n
    
    return False

def checkPrime(n : int, numTries : int = 15) -> bool:
    for _ in range(numTries):
        if not doMillerRabin(n):
            return False
    return True


def getNextPrime(start : int) -> bool :
    offsets = [1, 7, 11, 13, 17, 19, 23, 29]
    for offset in offsets:
        if checkPrime(start + offset):
            return start + offset
    return getNextPrime(start + 30)

def genKey() -> tuple[tuple[int]]:
    # generate p
    z = random.randrange(10**100, 10**101)
    p = getNextPrime(30 * z)
    
    # generate q
    z = random.randrange(10**100, 10**101)
    q = getNextPrime(30 * z)

    # generate d (For a prime d > max{p, q} we get ggT(d, phi(n)) = 1)
    d = getNextPrime(30 * (max(p, q) // 30 + 1))
    
    e = rsa.mudularInverse(d, (p-1)*(q-1))
    n = p * q
    return ((e, n), (d, n))

# finds p, q for a given n using difference of squares
def findFactors(n : int) -> tuple[int]:
    isSquare = lambda x : int(x**0.5)**2 == x

    u = int(n**0.5) + 1
    while not isSquare(u**2-n):
        u += 1

    w = int((u**2-n)**0.5)

    return (u+w, u-w)
    

(encryptKey, decryptKey) = genKey()
cryptotext = rsa.rsa([12, 42, 1, 0, 76, 30], encryptKey)
print(cryptotext)
print(rsa.rsa(cryptotext, decryptKey))

print(findFactors(9854989 * 9857213))
