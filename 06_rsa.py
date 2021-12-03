def powWithMod(base : int, exponent : int, mod : int) -> int:
    res = 1
    digit = 0

    while (exponent >> digit) > 0:
        if (exponent & (1 << digit)) > 0:
            res = (res * base) % mod
        
        base = (base * base) % mod
        digit += 1

    return res

def extendedEucildianAlgorithm(a : int, b : int) -> tuple[int]:
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
    return (extendedEucildianAlgorithm(num, mod)[1] + mod) % mod


def rsa(text : list[int], key : tuple[int]):
    return [ powWithMod(t, key[0], key[1]) for t in text ]


encryptKey = (53, 77)
cryptotext = rsa([12, 42, 1, 0, 76, 30], encryptKey)
print(cryptotext)

decryptKey = (mudularInverse(encryptKey[0], 10 * 6), encryptKey[1])
print(rsa(cryptotext, decryptKey))
print((encryptKey[0] * decryptKey[0]) % (10 * 6))



