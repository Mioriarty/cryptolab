import random

aes         = __import__("03_aes")
aes_key_gen = __import__("04_aes_key_gen")


def xor(a1 : bytearray, a2 : bytearray) -> bytearray:
    """
    Xors 2 bytearrays.

    Args:
        m1 (bytearray): bytearray 1
        m2 (bytearray): bytearray 1

    Returns:
        bytearray: Xored bytearray
    """
    return bytearray([a1[i] ^ a2[i] for i in range(len(a1))])


def cbcMAC(message : bytearray, aesKeys : list[bytearray]) -> bytearray:
    """
    Computes a cbc-MAC using the AES system.

    Expects message that's length is a multiple of 128 bits = 16 bytes.

    Args:
        message (bytearray): Message to be hashed. Expects message that's length is a multiple of 128 bits = 16 bytes.
        aesKeys (list[bytearray]): All aes round keys to be used

    Returns:
        bytearray: The resulting hash
    """
    # split message in blocks
    blocks = [ message[16*i : 16*(i+1)] for i in range(len(message) // 16) ]

    # start with IV all zeros
    crntHash = bytearray(16) 

    # encrypt all blocks and add it to the previuous result
    for block in blocks:
        crntHash = aes.encipher(xor(block, crntHash), aesKeys)
    
    return crntHash

def aesCtrMode(message : bytearray, aesKeys : list[bytearray], ctr : int) -> bytearray:
    """
    Enciphers and deciphers a plaintext of any length using the electronic code block mode and the AES cipher.

    It can do both because the ctr mode is involutoric.

    Args:
        message (bytearray): PLaintext / Ciphertext.
        aesKeys (list[bytearray]): All AES round keys.
        ctr (int): The ctr nonce value. Should be different every time!

    Returns:
        bytearray: The encrypted / decrypted message
    """
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
    """
    Enciphers a message using aes in the ccm mode.

    Args:
        message (bytearray): Message to be enciphered.
        key (bytearray): AES key.
        ctr (int): The ctr nonce value. Should be different every time!

    Returns:
        bytearray: The enciphered message.
    """
    aesKeys = aes_key_gen.genKeys(key)
    y = aesCtrMode(message, aesKeys, ctr)
    return y + cbcMAC(y, aesKeys)


def decipherCcm(cyphertext : bytearray, key : bytearray, ctr : int) -> bytearray:
    """
    Deciphers and checks integrity of a ciphertext using aes in the ccm mode.

    Args:
        cyphertext (bytearray): The ciphertext
        key (bytearray): aes key
        ctr (int): The ctr nonce value. Should be different every time!

    Raises:
        ValueError: When the integrity has been falsified.

    Returns:
        bytearray: The encrypted message.
    """
    aesKeys = aes_key_gen.genKeys(key)
    hashVal = cyphertext[-16:]
    cyphertext = cyphertext[:-16]

    if cbcMAC(cyphertext, aesKeys) != hashVal:
        raise ValueError("The ciphertext has been changed and thus is not valid anymore")
    
    plaintext = aesCtrMode(cyphertext, aesKeys, ctr)
    
    # trim zeros
    while plaintext[-1] == 0:
        plaintext = plaintext[:-1]

    return plaintext
    

if __name__ == "__main__":
    key = bytearray("Balko ist cooler", "UTF-8")
    text = "Hallo ich hoffe du kommst Ende nachmal raus. Das heisst naehmlich, dass das was ich gemacht habe, gar nicht so schlecht ist :)"
    ctr = int.from_bytes(random.randbytes(8), byteorder='big')

    c = encipherCcm(bytearray(text, 'UTF-8'), key, ctr)
    print(decipherCcm(c, key, ctr))
    c = bytearray([ 5 ]) + c[1:]
    print(decipherCcm(c, key, ctr))
