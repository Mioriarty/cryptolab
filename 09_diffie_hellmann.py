import random

rsa = __import__("06_rsa")
rsa_key_gen = __import__("07_rsa_key_gen")

def calcTransmitValue(p : int, g : int) -> tuple[int]:
    """
    Generates transmit value (= half key) and secret value from public values.

    Args:
        p (int): Modolus
        g (int): Generator (Base)

    Returns:
        tuple[int]: transmit value (= half key), private value
    """
    a = random.randint(2, p-1)
    return rsa.powWithMod(g, a, p), a

def calcSecretFromTransmitValue(transmitVal : int, p : int, a : int) -> int:
    """
    Calculates the secret (eg key) from public values and the transmitted value (= half key of the other participant)

    Args:
        transmitVal (int): transmitted value (= half key of the other participant)
        p (int): Modolus
        a (int): Own private value

    Returns:
        int: Claculated secret (eg key)
    """
    return rsa.powWithMod(transmitVal, a, p)

def genPublicValues(range : tuple[int] = (10**10, 10**20)) -> tuple[int]:
    """
    Generates a modulus and a generator for a diffie hellman exchange.

    If we find a q such that p = 2q + 1 is also prime, than every 1 < g < p-1 is suitable (not necessary a generator) with modulus p.

    Args:
        range (tuple[int], optional): The range of the prime search. While searching the value will be mutiplied by 30. Defaults to (10**10, 10**20).

    Returns:
        tuple[int]: Modulus p, Generator g
    """
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