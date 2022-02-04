import numpy as np
import random

class Qubit:

    STANDART_BASIS = [ np.array((1, 0)), np.array((0, 1)) ]
    HADAMART_BASIS = [ np.array((1, 1)) / np.sqrt(2), np.array((1, -1)) / np.sqrt(2) ]

    # state is either a vector in the specified basis or the index of the basis vector
    def __init__(self, state : np.ndarray | int, basis : list[np.ndarray] = STANDART_BASIS):
        if isinstance(state, int):
            self.__state = basis[state]
        else:
            self.__state = np.array(basis).dot(state)
    
    def measure(self, basis : list[np.ndarray]) -> int:
        # returns index of basis vector that got measured
        props = [ np.dot(baseVector, self.__state)**2 for baseVector in basis ]

        return random.choices(list(range(len(basis))), props)[0]

    @classmethod
    def randomBit(cls) -> int:
        return cls(0).measure(cls.HADAMART_BASIS)
    
# Alice's job
def generateSetOfRandomBits(n : int) -> tuple[list[int], list[int], list[Qubit]]:
    a = [ Qubit.randomBit() for _ in range(n) ]
    basisChoice = [ Qubit.randomBit() for _ in range(n) ]

    qubits = [ Qubit(a[i], Qubit.STANDART_BASIS if basisChoice[i] == 0 else Qubit.HADAMART_BASIS) for i in range(n) ]

    return a, basisChoice, qubits

# Bob's job
def readQubitsRondomly(qubits : list[Qubit]) -> tuple[list[int], list[int]]:
    basisChoice = [ Qubit.randomBit() for _ in range(len(qubits))]

    readBits = [ qubits[i].measure(Qubit.STANDART_BASIS if basisChoice[i] == 0 else Qubit.HADAMART_BASIS) for i in range(len(qubits)) ]

    return readBits, basisChoice

# sould be done by both
def compareAndDiscardBits(basisChoice1 : list[int], basisChoice2 : list[int], bits : list[int]) -> list[int]:
    return [ bits[i] for i in range(len(bits)) if basisChoice1[i] == basisChoice2[i] ]

# to check whether Eve was listening
def extractRandomBits(bits : list[int], k : int, seed : int) -> tuple[list[int], list[int]]:
    extractedBits = []
    random.seed(seed)

    for _ in range(k):
        index = random.randrange(0, len(bits))
        extractedBits.append(bits[index])
        bits = bits[:index] + bits[index+1:]
    
    return bits, extractedBits



aliceBits, aliceBasisChoice, qubits = generateSetOfRandomBits(100)
bobsBits, bobsBasisChoice = readQubitsRondomly(qubits)

# they exchange now their chosen basis

key1 = compareAndDiscardBits(aliceBasisChoice, bobsBasisChoice, aliceBits)
key2 = compareAndDiscardBits(aliceBasisChoice, bobsBasisChoice, bobsBits)
# key1 == key2 should be the case

# check whether Eve was listening
seed = random.randint(0, 1 << 32)
key1, extracedBits1 = extractRandomBits(key1, 15, seed)
key2, extracedBits2 = extractRandomBits(key2, 15, seed)

if extracedBits1 != extracedBits2:
    print("EVE WAS LISTENING")
else:
    print("The key is")
    print("".join(str(k) for k in key1))
    print("".join(str(k) for k in key2))

