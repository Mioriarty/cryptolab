from numpy import log2, uint8, uint16
import random


def generateSPN(sBox : list[uint8], pBox : list[uint8], numRounds : int):


    def encipher(plaintext : uint16, keys : list[uint16]) -> uint16:
        cryptotext = plaintext

        for round in range(numRounds):
            # key addition
            cryptotext = cryptotext ^ keys[round]

            # substitution
            temp = uint16(0)
            for chunk in range(3, -1, -1):
                chunkValue = (cryptotext >> (chunk * 4)) & 0b1111
                temp <<= 4
                temp += sBox[round][chunkValue]
            cryptotext = temp

            # permutation
            temp = uint16(0)
            for bit in range(15, -1, -1):
                temp <<= 1
                temp += (cryptotext >> pBox[round][bit]) & 1
            cryptotext = temp
        
        cryptotext = cryptotext ^ keys[numRounds]
        
        return cryptotext
    
    return encipher


def bindKeysToSPN(spn, keys : list[bytearray]):
    return lambda plaintext : spn(plaintext, keys)

def countSetBits(n : uint16) -> int:
    if n == 0:
        return 0
    else:
        return (n & 1) + countSetBits(n >> 1)

def doLinearAnalysis(plainCryptoPairs : list[tuple[uint16]], includedInputs : uint16, includedOutputs : uint16) -> uint16:
    includedOutputsList = [k for k in range(16) if (includedOutputs >> k) & 1 != 0]

    keyBiases = {}

    for smushedKey in range(1 << len(includedOutputsList)):
        # Example:
        # includedOutputs: 0b1010000010100000
        # smushedKey:      0b1011
        # key:             0b1000000010100000


        # bit representation as list
        smushedKey = [(smushedKey >> k) & 1 for k in range(len(includedOutputsList))]
        
        # generate expended key over relevant bits
        key = uint16(sum([smushedKey[i] << includedOutputsList[i] for i in range(len(includedOutputsList))]))
        
        succeededAttemps = 0
        for plaintext, cryptotext in plainCryptoPairs:
            guessedBeforeLastRound = cryptotext ^ key
            
            filteredPlaintext = plaintext & includedInputs
            filteredGuess = guessedBeforeLastRound & includedOutputs

            if (countSetBits(filteredPlaintext) + countSetBits(filteredGuess)) % 2 == 0:
                succeededAttemps += 1
        
        print(succeededAttemps)
        bias = (succeededAttemps / len(plainCryptoPairs)) - 1/2

        keyBiases[key] = bias

    print(keyBiases)
    bestKey = max(keyBiases, key = lambda e : abs(keyBiases[e]))
    return bestKey
        




SBOX = [ 0xE, 0x4, 0xD, 0x1, 0x2, 0xF, 0xB, 0x8, 0x3, 0xA, 0x6, 0xC, 0x5, 0x9, 0x0, 0x7 ]
PBOX = [ 0x0, 0x4, 0x8, 0xC, 0x1, 0x5, 0x9, 0xD, 0x2, 0x6, 0xA, 0xE, 0x3, 0x7, 0xB, 0xF ]
KEY  = 0xABCD

spn = bindKeysToSPN(generateSPN([SBOX]*4, [PBOX]*4, 4), [KEY]*5)

# generate plaintext cryptotext pairs
plainCryptoPairs = []
for _ in range(8000):
    plaintext = uint16(int(random.uniform(0, 2**16-1)))
    plainCryptoPairs.append((plaintext, spn(plaintext)))


print(doLinearAnalysis(plainCryptoPairs, 0b0000000011010000, 0b1010000010100000))
print(KEY & 0b1010000010100000)


spn = bindKeysToSPN(generateSPN([list(range(0, 16))] * 4, [list(range(0, 16))] * 4, 4), [0]*5)
p = uint16(12345)
print(spn(p))
