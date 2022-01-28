aes = __import__("03_aes")

# takes a 128 bit key and returns 11x 128 bit round keys
def genKeys(key : bytearray) -> list[bytearray]:
    # subdivide into 4x 4 byte chunks
    w = [ key[4*i : 4*(i+1)] for i in range(4) ]

    for i in range(4, 44):
        if i % 4 == 0:
            w.append(xor(xor(w[i-1], rcon(i//4)), subWord(rotWord(w[i-1]))))
        else:
            w.append(xor(w[i-4], w[i-1]))

    # subdivide into 11 round keys
    keys = [ w[i] + w[i+1] + w[i+2] + w[i+3] for i in range(0, 44, 4) ]
    return keys

def rcon(i : int) -> bytearray:
    RC = [ 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36 ]
    return bytearray([ RC[i-1], 0, 0, 0 ])

# takes in 4 byte word and rotates it
def rotWord(word : bytearray) -> bytearray:
    return bytearray([word[(i+1) % 4] for i in range(4)])

# takes in 4 byte word and substitute single bytes
def subWord(word : bytearray) -> bytearray:
    return bytearray([aes.SBOX[b] for b in word])

def xor(a1 : bytearray, a2 : bytearray) -> bytearray:
    return bytearray([a1[i] ^ a2[i] for i in range(4)])


def encipherECB(plaintext : str, key : bytearray) -> bytearray:
    # split message in blocks
    plaintext += "\0" * 15
    plaintextBlocks = [bytearray(plaintext[16*i : 16*(i+1)], 'UTF-8') for i in range(len(plaintext) // 16)]

    keys = genKeys(key)
    ciphertextBlocks = [ aes.encipher(block, keys) for block in plaintextBlocks ]
    
    # combine all ciphertext blocks
    ciphertext = bytearray()
    for block in ciphertextBlocks:
        ciphertext += block
    return ciphertext

def decipherECB(ciphertext : bytearray, key : bytearray) -> str:
    # split message in blocks
    ciphertextBlocks = [ciphertext[16*i : 16*(i+1)] for i in range(len(ciphertext) // 16)]

    keys = genKeys(key)
    plaintextBlocks = [ aes.decipher(block, keys).decode() for block in ciphertextBlocks ]

    # combine all plaintextblocks blocks
    plaintext = "".join(plaintextBlocks)

    # remove 0 bytes at the end
    while plaintext[-1] == "\0":
        plaintext = plaintext[:-1]
    
    return plaintext

if __name__=='__main__':
    key = bytearray("Balko ist cooler", "UTF-8")
    text = "Hallo ich hoffe du kommst Ende nachmal raus. Das heisst naehmlich, dass das was ich gemacht habe, gar nicht so schlecht ist :)"
    cipher = encipherECB(text, key)
    print(cipher)
    print(decipherECB(cipher, key))