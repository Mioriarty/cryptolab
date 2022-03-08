def powWithMod(base : int, exponent : int, mod : int) -> int:
    """
    Computes a modular power efficiently by using squaring and multiplying.

    Args:
        base (int): Base
        exponent (int): Exponent / Power
        mod (int): Mode

    Returns:
        int: The result of the computation.
    """
    res = 1
    digit = 0

    while (exponent >> digit) > 0:
        if (exponent & (1 << digit)) > 0:
            res = (res * base) % mod
        
        base = (base * base) % mod
        digit += 1

    return res

def extendedEucildianAlgorithm(a : int, b : int) -> tuple[int]:
    """
    Performs the extended euklidian algorithm with paramenters a, b.

    Args:
        a (int): First parameter.
        b (int): Secodn parameter.

    Returns:
        tuple[int]: (r, s, t) such that gcd(a, b) = r = s * a + b * t
    """
    prevR = a
    crntR = b
    prevS = 1
    crntS = 0
    prevT = 0
    crntT = 1
    

    while True:
        q = prevR // crntR
        nextR = prevR - q * crntR
        nextS = prevS - q * crntS
        nextT = prevT - q * crntT

        if nextR == 0:
            return crntR, crntS, crntT
        
        # update for next round
        prevR, crntR = crntR, nextR
        prevS, crntS = crntS, nextS
        prevT, crntT = crntT, nextT

def mudularInverse(num : int, mod : int) -> int:
    """
    Computes the inverse of a number modolu another number.

    Basically performes the extended euklidian algorithm and extracts the right values.

    Args:
        num (int): The number that sjhould be inverted.
        mod (int): The modulus.

    Returns:
        int: The inverse of num.
    """
    return (extendedEucildianAlgorithm(num, mod)[1] + mod) % mod


def rsa(text : int | list[int], key : tuple[int]) -> int | list[int]:
    """
    Performs the rsa encryption / decryption. (Depends on the given key)

    Args:
        text (int | list[int]): Either a message or a list of messages that should be encrypted. The message should be an integer. 
        key (tuple[int]): Consists of (x, n) where n is the modulus and x is either the private or public key.

    Returns:
        int | list[int]: The encrypted message(s).
    """
    if isinstance(text, list):
        return [ powWithMod(t, key[0], key[1]) for t in text ]
    else:
        return powWithMod(text, key[0], key[1])


if __name__ == "__main__":
    encryptKey = (53, 77)
    cryptotext = rsa([12, 42, 1, 0, 76, 30], encryptKey)
    print(cryptotext)

    decryptKey = (mudularInverse(encryptKey[0], 10 * 6), encryptKey[1])
    print(rsa(cryptotext, decryptKey))

    # inverse checks out :)
    print((encryptKey[0] * decryptKey[0]) % (10 * 6))



