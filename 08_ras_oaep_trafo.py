import random
import hashlib

rsa = __import__("06_rsa")
keyGen = __import__("07_rsa_key_gen")

def getByteLength(n : int) -> int:
    length = 0
    while (n := n >> 8) > 0:
        length += 1
    return length + 1

def xor(m1 : bytearray, m2 : bytearray) -> bytearray:
    return bytearray([ b1 ^ b2 for (b1, b2) in zip(m1, m2) ])

def mgf1(seed : bytearray, length : int, hashfunction) -> bytearray:
    counter = 0
    T = bytearray()

    while len(T) <= length:
        counter += 1
        T += hashfunction(seed + bytearray(counter.to_bytes(4, 'big')))
    
    return T[:length]

def oaepTrafo(message : bytearray, n : int, hashfunction, l : bytearray = bytearray()) -> bytearray:
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

def invOeapTrafo(message : bytearray, hashfunction, l : bytearray = bytearray()) -> bytearray:
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
    trafoedMsg = oaepTrafo(message, key[1], hashFun)
    return rsa.rsa([ int.from_bytes(trafoedMsg, 'big', signed=False) ], key)[0]

def decryptRsaWithTrafo(message : int, key : tuple[int]) -> bytearray:
    encrypted = rsa.rsa([ message ], key)[0]
    return invOeapTrafo(encrypted.to_bytes(getByteLength(encrypted) + 1, 'big'), hashFun)

if __name__ == "__main":
    # wrapper around sha1 to convert return value to bytearray
    hashFun = lambda m : bytearray(hashlib.sha1(m).digest())

    (encryptKey, decryptKey) = keyGen.genKey()
    message = bytearray([1, 2, 3, 0])

    cryptotext = encryptRsaWithTrafo(message, encryptKey)
    print(decryptRsaWithTrafo(cryptotext, decryptKey))


