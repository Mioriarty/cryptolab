import random

rsa = __import__("06_rsa")

def doMillerRabin(n : int) -> bool:
    """
    Does one iteration of the miller rabin test.

    Args:
        n (int): The value that will be checked against.

    Returns:
        bool: Returns whether this iteration of the test thinks that n is prime. If false is returned, n is defenitely not prime. If true, it might still be compound.
    """
    # discard even inputs
    if n % 2 == 0:
        return False

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
    """
    Checks whether n is prime by performing miller rabin multiple times.

    A return value of false is always coorect while a true might be falsed (although that is really unlikely)

    Args:
        n (int):  The value that will be checked against its primness.
        numTries (int, optional): How many times should miller rabin be executed. Defaults to 15.

    Returns:
        bool: _description_
    """
    for _ in range(numTries):
        if not doMillerRabin(n):
            return False
    return True


def getNextPrime(start : int) -> int:
    """
    Returns the next prime after start. Start has to be divisible by 30.

    Args:
        start (int): The value where the searching starts. It has to be divisible by 30.

    Raises:
        ValueError: When start is not divisible by 30.

    Returns:
        int: The next prime number after start
    """

    if start % 30 != 0:
        raise ValueError("Start has to be divisble by 30")

    offsets = [1, 7, 11, 13, 17, 19, 23, 29]
    for offset in offsets:
        if checkPrime(start + offset):
            return start + offset
    return getNextPrime(start + 30)

def genKey() -> tuple[tuple[int]]:
    """
    Generates a RSA key pair.

    Returns:
        tuple[tuple[int]]: Returns tuple of public and private keys.
    """
    # generate p
    z = random.randrange(10**100, 10**101)
    p = getNextPrime(30 * z)
    
    # generate q
    z = random.randrange(10**100, 10**101)
    q = getNextPrime(30 * z)

    # generate d (For a prime d > max{p, q} we get gcd(d, phi(n)) = 1)
    d = getNextPrime(30 * (max(p, q) // 30 + 1))
    
    e = rsa.mudularInverse(d, (p-1)*(q-1))
    n = p * q
    return ((e, n), (d, n))

def findFactors(n : int) -> tuple[int]:
    """
    Tries to find the factors of a number assuming they are close by. If they are not, the search will take forever.

    The used method is the difference of squares:
        Assume: n = (u-d)*(u+d) = u² - d² <=> d² = u² - n
        => If we find a u such that u² - n is a perfect square, we found our p = u-d, q = u+d such that n = p*q

    Args:
        n (int): The number that shoule factored

    Returns:
        tuple[int]: The factors of n.
    """
    isSquare = lambda x : int(x**0.5)**2 == x

    u = int(n**0.5) + 1
    while not isSquare(u**2-n):
        u += 1

    w = int((u**2-n)**0.5)

    return (u+w, u-w)
    
if __name__ == "__main__":
    (encryptKey, decryptKey) = genKey()
    cryptotext = rsa.rsa([12, 42, 1, 0, 76, 30], encryptKey)
    print(cryptotext)
    print(rsa.rsa(cryptotext, decryptKey))

    print(findFactors(9854989 * 9857213))
    print(findFactors(9999749 * 3005293))

    # print(findFactors(5000000037041 * 10000000058171))
