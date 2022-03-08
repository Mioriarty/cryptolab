import random

rsa = __import__("06_rsa")
rsa_key_gen = __import__("07_rsa_key_gen")

def calcTransmitValue(p : int, g : int):
    a = random.randint(2, p-1)
    return rsa.powWithMod(g, a, p), a

def calcSecretFromTransmitValue(transmitVal : int, p : int, a : int):
    return rsa.powWithMod(transmitVal, a, p)

def genPublicValues(range : tuple[int] = (10**10, 10**20)):
    while True:
        # get a prime q
        z = random.randrange(range[0], range[1])
        q = rsa_key_gen.getNextPrime(30 * z)

        p = 2 * q + 1

        if rsa_key_gen.checkPrime(p):
            # found a prime. whohoo
            g = random.randrange(2, p-2)
            return p, g


if __name__ == "__main__":
    p, g = genPublicValues()

    t1, a1 = calcTransmitValue(p, g)
    t2, a2 = calcTransmitValue(p, g)

    print(calcSecretFromTransmitValue(t2, p, a1))
    print(calcSecretFromTransmitValue(t1, p, a2))