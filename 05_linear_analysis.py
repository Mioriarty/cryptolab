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
                temp ^= sBox[round][chunkValue]
            cryptotext = temp

            # permutation
            if round < numRounds-1:
                temp = uint16(0)
                for bit in range(16):
                    temp ^= ((cryptotext >> bit) & 1) << pBox[round][bit]
                cryptotext = temp
        

        cryptotext = cryptotext ^ keys[numRounds]
        
        return cryptotext
    
    return encipher


def bindKeysToSPN(spn, keys : list[uint16]):
    return lambda plaintext : spn(plaintext, keys)

def countSetBits(n : uint16) -> int:
    if n == 0:
        return 0
    else:
        return (n & 1) + countSetBits(n >> 1)

def doLinearAnalysis(plainCryptoPairs : list[tuple[uint16]], sBox : list[uint16], approximationInputs : uint16, approximationLastRound : uint16) -> uint16:
    # calculate inverse sBox
    sBoxInv = [0] * 16
    for index, val in enumerate(sBox):
        sBoxInv[val] = index
    

    # start with actual linear analysis
    keyBiases = {}

    # which chunks do we have to include in the key search
    includedChunks = [i for i in range(4) if ((approximationLastRound >> i*4) & 0b1111) != 0]

    for smushedKey in range(1 << (len(includedChunks) * 4)):
        key = uint16(0)
        for chunkIndex, chunk in enumerate(includedChunks):
            key ^= (smushedKey >> (chunkIndex * 4) & 0b1111) << (chunk * 4)
        
        print("{:16b}".format(key))
        
        succeededAttemps = 0
        for plaintext, cryptotext in plainCryptoPairs:
            # backwards key addition
            guessed = cryptotext ^ key

            # backward substitution
            guessedBeforeSub = uint16(0)
            for chunk in range(3, -1, -1):
                chunkValue = (guessed >> (chunk * 4)) & 0b1111
                guessedBeforeSub <<= 4
                guessedBeforeSub ^= sBoxInv[chunkValue]
            
            # check linear approximation
            filteredPlaintext = approximationInputs & plaintext
            filteredBeforeSub = approximationLastRound & guessedBeforeSub

            if (countSetBits(filteredPlaintext) + countSetBits(filteredBeforeSub)) % 2 == 0:
                succeededAttemps += 1
        
        bias = (succeededAttemps / len(plainCryptoPairs)) - 1/2
        keyBiases[key] = bias
    
    bestKey = max(keyBiases, key = lambda e : abs(keyBiases[e]))
    return bestKey


SBOX = [ 0xE, 0x4, 0xD, 0x1, 0x2, 0xF, 0xB, 0x8, 0x3, 0xA, 0x6, 0xC, 0x5, 0x9, 0x0, 0x7 ]
PBOX = [ 0x0, 0x4, 0x8, 0xC, 0x1, 0x5, 0x9, 0xD, 0x2, 0x6, 0xA, 0xE, 0x3, 0x7, 0xB, 0xF ]
KEY  = 0x1Ab2

spn = bindKeysToSPN(generateSPN([SBOX]*4, [PBOX]*4, 4), [KEY]*5)


# generate plaintext cryptotext pairs
plainCryptoPairs = []
for _ in range(8000):
    plaintext = uint16(int(random.uniform(0, 2**16-1)))
    plainCryptoPairs.append((plaintext, spn(plaintext)))


# guessedKey = doLinearAnalysis(plainCryptoPairs, SBOX, 0b0000000011010000, 0b1010000010100000)
guessedKey = doLinearAnalysis(plainCryptoPairs, SBOX, 0b0000101100000000, 0b0000010100000101)
print("\nGuessed Key:")
print("{:16b}".format(guessedKey))
print("Actual Key:")
print("{:16b}".format(KEY))
