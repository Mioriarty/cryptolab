import random
import hashlib
from typing import Callable

rsa = __import__("06_rsa")
keyGen = __import__("07_rsa_key_gen")
sha1 = __import__("11_sha1")

#  +----+ +----------+ +-----------+--------+----+-----------+
#  | 00 | |   seed   | |   lHash   |   PS   | 01 |     M     |
#  +----+ +----------+ +-----------+--------+----+-----------+
#    |        |                          |
#    |        |                          V
#    |        +-------> MGF ------------>⊕
#    |        |                          |
#    |        V                          |
#    |        ⊕<------ MGF <------------+
#    |        |                          |
#    V        V                          V
#  +----+ +----------+ +-------------------------------------+
#  | 00 | |maskedSeed| |              maskedDB               |
#  +----+ +----------+ +-------------------------------------+
#
# seed: Random seed. Different for each method. With len(seed) = len(lHash)
# lHash: hash(l) where l is an optional parameter. Defaults to empty bytearray
# PS: Array of zeros, such that len(n) = len(m) + len(PS) + 2*len(lHash) + 2, where n is the RSA modulus
# M: message with th restriction that len(m) ≤ len(n) - 2*len(lHash) - 2


def getByteLength(n : int) -> int:
    """
    Get count of bytes that a number occupies.

    Args:
        n (int): The number, the bytes sould be counted of.

    Returns:
        int: The number of bytes of the number.
    """
    length = 0
    while (n := n >> 8) > 0:
        length += 1
    return length + 1

def xor(m1 : bytearray, m2 : bytearray) -> bytearray:
    """
    Xors 2 bytearrays.

    Args:
        m1 (bytearray): bytearray 1
        m2 (bytearray): bytearray 1

    Returns:
        bytearray: Xored bytearray
    """
    return bytearray([ b1 ^ b2 for (b1, b2) in zip(m1, m2) ])

def mgf1(seed : bytearray, length : int, hashfunction : Callable[[bytearray], bytearray]) -> bytearray:
    """
    One possible implementation of the mask generating function.

    Args:
        seed (bytearray): The random seed used.
        length (int): Desired output length
        hashfunction (Callable[[bytearray], bytearray]): Hashfunction to be used.

    Returns:
        bytearray: The generated mask.
    """
    counter = 0
    T = bytearray()

    while len(T) <= length:
        counter += 1
        T += hashfunction(seed + bytearray(counter.to_bytes(4, 'big')))
    
    return T[:length]

def oaepTrafo(message : bytearray, n : int, hashfunction : Callable[[bytearray], bytearray], l : bytearray = bytearray()) -> bytearray:
    """
    Performs the OAEP-transformation. For detailed information see the draft in the beginning of the document.

    Args:
        message (bytearray): Message to be encrypted
        n (int): The RSA modulus.
        hashfunction (Callable[[bytearray], bytearray]): The hashfunction used.
        l (bytearray, optional): Value of l. Defaults to bytearray().

    Raises:
        ValueError: If the message is too long. (len(m) > len(n) - 2*len(lHash) - 2)

    Returns:
        bytearray: The transformed message.
    """
    lHash = hashfunction(l)
    zeroArrayLength = getByteLength(n) - 2 * len(lHash) - 2 - len(message)
    
    if zeroArrayLength < 0:
        raise ValueError("Message too long")
    
    PS = bytearray(zeroArrayLength)

    seed = bytearray(random.randbytes(len(lHash)))

    db = lHash + PS + bytearray([ 1 ]) + message

    maskedDB = xor(mgf1(seed, len(db), hashfunction), db)
    maskedSeed = xor(mgf1(maskedDB, len(seed), hashfunction), seed)

    return bytearray(1) + maskedSeed + maskedDB

def invOeapTrafo(message : bytearray, hashfunction : Callable[[bytearray], bytearray], l : bytearray = bytearray()) -> bytearray:
    """
    Inverts the oaep transformation.

    Args:
        message (bytearray): The message
        hashfunction (Callable[[bytearray], bytearray]): The hash function in use.
        l (bytearray, optional): Value of l. Defaults to bytearray().

    Returns:
        bytearray: The extracted message
    """
    lHash = hashfunction(l)

    maskedSeed = message[1:1+len(lHash)]
    maskedDB   = message[1+len(lHash):]

    seed = xor(mgf1(maskedDB, len(maskedSeed), hashfunction), maskedSeed)
    db = xor(mgf1(seed, len(maskedDB), hashfunction), maskedDB)

    message = db[len(lHash):]
    while message[0] == 0:
        message = message[1:]
    
    return message[1:] # cut of the last 1

def encryptRsaWithTrafo(message : bytearray, key : tuple[int]) -> int:
    """
    Encrypts a message with RSA including a oaep trafo.

    Args:
        message (bytearray): Plaintext.
        key (tuple[int]): The encrpytion key for the RSA.

    Returns:
        int: The ciphertext.
    """
    trafoedMsg = oaepTrafo(message, key[1], hashFun)
    return rsa.rsa([ int.from_bytes(trafoedMsg, 'big', signed=False) ], key)[0]

def decryptRsaWithTrafo(message : int, key : tuple[int]) -> bytearray:
    """
    Decrypts a message with RSA including a oaep trafo.

    Args:
        message (int): Ciphertext.
        key (tuple[int]): The decryption key for the RSA.

    Returns:
        bytearray: The Plaintext.
    """
    encrypted = rsa.rsa([ message ], key)[0]
    return invOeapTrafo(encrypted.to_bytes(getByteLength(encrypted) + 1, 'big'), hashFun)

if __name__ == "__main__":
    # wrapper around sha1 to convert return value to bytearray
    hashFun = lambda m : bytearray(sha1.sha1(m).to_bytes(20, 'big'))

    (encryptKey, decryptKey) = keyGen.genKey()
    message = bytearray([1, 2, 3, 0])
    print(oaepTrafo(message, decryptKey[1], hashFun))

    cryptotext = encryptRsaWithTrafo(message, encryptKey)
    print(decryptRsaWithTrafo(cryptotext, decryptKey))

