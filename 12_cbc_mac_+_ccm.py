import random

aes         = __import__("03_aes")
aes_key_gen = __import__("04_aes_key_gen")


def xor(a1 : bytearray, a2 : bytearray) -> bytearray:
    return bytearray([a1[i] ^ a2[i] for i in range(len(a1))])

# symmetric hash function to check whether the encrypted message has been changed
# expects message that's length is a multiple of 128 bits = 16 bytes
def cbcMAC(message : bytearray, aesKeys : list[bytearray]) -> bytearray:
    # split message in blocks
    blocks = [ message[16*i : 16*(i+1)] for i in range(len(message) // 16) ]

    # start with IV all zeros
    crntHash = bytearray(16) 

    # encrypt all blocks and add it to the previuous result
    for block in blocks:
        crntHash = aes.encipher(xor(block, crntHash), aesKeys)
    
    return crntHash

# is involutoric thus doesn decryption and encryption
def aesCtrMode(message : bytearray, aesKeys : list[bytearray], ctr : int) -> bytearray:
    # add 0 padding if the length of msg is not multiple of 16 bytes = 128 bits
    if len(message) % 16 != 0:
        message += bytearray(16 - (len(message) % 16))

    # split message in blocks
    blocks = [ message[16*i : 16*(i+1)] for i in range(len(message) // 16) ]

    res = bytearray()

    for block in blocks:
        res += xor(aes.encipher(ctr.to_bytes(8, byteorder='big'), aesKeys), block)
        ctr += 1
    
    return res

def encipherCcm(message : bytearray, key : bytearray, ctr : int) -> bytearray:
    aesKeys = aes_key_gen.genKeys(key)
    y = aesCtrMode(message, aesKeys, ctr)
    return y + cbcMAC(y, aesKeys)


def decipherCcm(cyphertext : bytearray, key : bytearray, ctr : int) -> bytearray:
    aesKeys = aes_key_gen.genKeys(key)
    hashVal = cyphertext[-16:]
    cyphertext = cyphertext[:-16]

    if cbcMAC(cyphertext, aesKeys) != hashVal:
        raise ValueError("The ciphertext has been changed and thus is not valid anymore")
    
    # you could trim of the zeros, but its fiune i guess.
    # TODO
    return aesCtrMode(cyphertext, aesKeys, ctr)
    


key = bytearray("Balko ist cooler", "UTF-8")
text = "Hallo ich hoffe du kommst Ende nachmal raus. Das heisst naehmlich, dass das was ich gemacht habe, gar nicht so schlecht ist :)"
ctr = int.from_bytes(random.randbytes(8), byteorder='big')

c = encipherCcm(bytearray(text, 'UTF-8'), key, ctr)
print(decipherCcm(c, key, ctr))
c = bytearray([ 5 ]) + c[1:]
print(decipherCcm(c, key, ctr))
