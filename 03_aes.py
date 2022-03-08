from include.matrix import Matrix
import include.utils as utils

class GaloisElement:
    """
    Represents a element in the F_2^8-Field. Meaning the galois field with 256 elements.
    """

    def __init__(self, val : int):
        """
        Constructor of the GaloisElement class.

        Args:
            val (int): Integer representation of the galois element. Should be between 0 and 255.
        """
        self.val = val

    def double(self) -> None:
        """
        Doubles the value of itself. Takes care of overflow.
        """
        self.val = self.val << 1

        if self.val & 0b100000000:
            self.val = self.val ^ 0b100011011

    
    def __add__(self, other : 'GaloisElement') -> 'GaloisElement':
        """
        Adds to GaloisElements together.

        Basically it does an xor of its bits.

        Args:
            other (GaloisElement): The other element to add with.

        Returns:
            GaloisElement: The result of the addition.
        """
        return GaloisElement(bytes([self.val])[0] ^ bytes([other.val])[0])
    
    def __mul__(self, other : 'GaloisElement') -> 'GaloisElement':
        """
        Multiplies to GaloisElements together by doing Ancient Egyptian multiplication (Russische Bauersmultiplikation) which only requires adding and doubleing.

        Args:
            other (GaloisElement): The other element to multiply with.

        Returns:
            GaloisElement: The result of the multiplication.
        """
        stm = GaloisElement(0)
        otherVal = other.val
        selfCpy = GaloisElement(self.val)
        while otherVal > 0:
            if otherVal % 2 == 1:
                stm += selfCpy

            selfCpy.double()
            otherVal //= 2
        return stm

    def __str__(self):
        return "g{:08b}".format(self.val)


SBOX = []
SBOX_INV = []

def loadSBoxes():
    """
    Loads the AES S-boxes into their public variables.
    """
    global SBOX, SBOX_INV
    SBOX =  [ int(k, 16) for k in utils.getFileContent("03_SBox.txt").replace("\n", " ").split(", ") ]
    SBOX_INV = [ int(k, 16) for k in utils.getFileContent("03_SBoxInvers.txt").replace("\n", " ").split(", ") ]

def matToGalois(x : Matrix) -> Matrix:
    """
    Converts a Matrix of integers to a Matrix of GaloisElements with the respective values.

    Args:
        x (Matrix): Integer matrix. All entries should between 0 and 255.

    Returns:
        Matrix: The reuslting Matrix aof galois elements.
    """
    return Matrix(x.height, x.width, [ GaloisElement(int(e)) for e in x.vals ]) 

# *********** ENCIPHER *************

def encipher(plaintext : bytearray, keys : list[bytearray]) -> bytearray:
    """
    Enciphers a plaintext with the AES cipher.

    Args:
        plaintext (bytearray): Plaintext. Must be of length 16 (bytes)
        keys (list[bytearray]): All round keys for the AES encryption. Every key must have a length  of 16 bytes and there must be 11 keys in total.

    Returns:
        bytearray: Ciphertext (16 bytes)
    """
    x = matToGalois(Matrix(4, 4, plaintext).transpose())
    x = addRoundKey(x, keys[0])
    
    for i in range(1, 10):
        x = subBytes(x)
        x = shiftRows(x)
        x = mixColums(x)
        x = addRoundKey(x, keys[i])
    
    x = subBytes(x)
    x = shiftRows(x)
    x = addRoundKey(x, keys[10])

    return bytearray(v.val for v in x.transpose().vals)

def addRoundKey(x : Matrix, key : bytearray) -> Matrix:
    """
    Adds the round key to the matrix. 

    Args:
        x (Matrix): The current aes matrix.
        key (bytearray): The round key. Must be of length 16 bytes.
    
    Returns:
        Matrix: The new aes matrix after the operation.
    """
    keyMat = matToGalois(Matrix(4, 4, key)).transpose()
    x += keyMat
    return x

def subBytes(x : Matrix) -> Matrix:
    """
    Substitutes all bytes in the Matrix using the S-box.

    Args:
        x (Matrix): The current aes matrix.
    
    Returns:
        Matrix: The new aes matrix after the operation.
    """
    for i in range(16):
        x.vals[i] = GaloisElement(SBOX[x.vals[i].val])
    return x

def shiftRows(x : Matrix) -> Matrix:
    """
    Shifts the rows as described in the aes standart.

    Args:
        x (Matrix): The current aes matrix.
    
    Returns:
        Matrix: The new aes matrix after the operation.
    """
    cpy = Matrix(4, 4, x.vals[:])
    for i in range(1, 4):
        for j in range(4):
            x[i, (j - i + 4) % 4] = cpy[i, j]
    return x

def mixColums(x : Matrix) -> Matrix:
    """
    Mixes the columns as described in the aes standart.

    Args:
        x (Matrix): The current aes matrix.
    
    Returns:
        Matrix: The new aes matrix after the operation.
    """
    factor = matToGalois(Matrix(4, 4, [
        2, 3, 1, 1,
        1, 2, 3, 1,
        1, 1, 2, 3,
        3, 1, 1, 2
    ]))
    factor.useAsZero(GaloisElement(0))

    return factor * x


# *************** DECIPHER ***************

def decipher(ciphertext : bytearray, keys : list[bytearray]):
    """
    Deciphers a ciphertext with the AES cipher.

    Args:
        plaintext (bytearray): Ciphertext. Must be of length 16 (bytes)
        keys (list[bytearray]): All round keys for the AES decryption. Every key must have a length of 16 bytes and there must be 11 keys in total.

    Returns:
        bytearray: Ciphertext (16 bytes)
    """
    x = matToGalois(Matrix(4, 4, ciphertext).transpose())

    x = addRoundKey(x, keys[10])
    x = shiftRowsInv(x)
    x = subBytesInv(x)

    for i in range(9, 0, -1):
        x = addRoundKey(x, keys[i])
        x = mixColumsInv(x)
        x = shiftRowsInv(x)
        x = subBytesInv(x)
    
    x = addRoundKey(x, keys[0])

    return bytearray(v.val for v in x.transpose().vals)


def subBytesInv(x : Matrix) -> Matrix:
    """
    Substitutes all bytes in the Matrix using the SBOX_INV-box.

    Args:
        x (Matrix): The current aes matrix.
    
    Returns:
        Matrix: The new aes matrix after the operation.
    """
    for i in range(16):
        x.vals[i] = GaloisElement(SBOX_INV[x.vals[i].val])
    return x

def shiftRowsInv(x : Matrix) -> Matrix:
    """
    Shifts the rows invertly as described in the aes standart.

    Args:
        x (Matrix): The current aes matrix.
    
    Returns:
        Matrix: The new aes matrix after the operation.
    """
    cpy = Matrix(4, 4, x.vals[:])
    for i in range(1, 4):
        for j in range(4):
            x[i, (j + i) % 4] = cpy[i, j]
    return x

def mixColumsInv(x : Matrix) -> Matrix:
    """
    Mixes the columns invertly as described in the aes standart.

    Args:
        x (Matrix): The current aes matrix.
    
    Returns:
        Matrix: The new aes matrix after the operation.
    """
    factor = matToGalois(Matrix(4, 4, [
        0xE, 0xB, 0xD, 9,
        9, 0xE, 0xB, 0xD,
        0xD, 9, 0xE, 0xB,
        0xB, 0xD, 9, 0xE
    ]))
    factor.useAsZero(GaloisElement(0))

    return factor * x
        

loadSBoxes()

if __name__ == '__main__':
    keys = [
        bytearray([0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6, 0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c]),
        bytearray([0xa0, 0xfa, 0xfe, 0x17, 0x88, 0x54, 0x2c, 0xb1, 0x23, 0xa3, 0x39, 0x39, 0x2a, 0x6c, 0x76, 0x05]),
        bytearray([0xf2, 0xc2, 0x95, 0xf2, 0x7a, 0x96, 0xb9, 0x43, 0x59, 0x35, 0x80, 0x7a, 0x73, 0x59, 0xf6, 0x7f]),
        bytearray([0x3d, 0x80, 0x47, 0x7d, 0x47, 0x16, 0xfe, 0x3e, 0x1e, 0x23, 0x7e, 0x44, 0x6d, 0x7a, 0x88, 0x3b]),
        bytearray([0xef, 0x44, 0xa5, 0x41, 0xa8, 0x52, 0x5b, 0x7f, 0xb6, 0x71, 0x25, 0x3b, 0xdb, 0x0b, 0xad, 0x00]),
        bytearray([0xd4, 0xd1, 0xc6, 0xf8, 0x7c, 0x83, 0x9d, 0x87, 0xca, 0xf2, 0xb8, 0xbc, 0x11, 0xf9, 0x15, 0xbc]),
        bytearray([0x6d, 0x88, 0xa3, 0x7a, 0x11, 0x0b, 0x3e, 0xfd, 0xdb, 0xf9, 0x86, 0x41, 0xca, 0x00, 0x93, 0xfd]),
        bytearray([0x4e, 0x54, 0xf7, 0x0e, 0x5f, 0x5f, 0xc9, 0xf3, 0x84, 0xa6, 0x4f, 0xb2, 0x4e, 0xa6, 0xdc, 0x4f]),
        bytearray([0xea, 0xd2, 0x73, 0x21, 0xb5, 0x8d, 0xba, 0xd2, 0x31, 0x2b, 0xf5, 0x60, 0x7f, 0x8d, 0x29, 0x2f]),
        bytearray([0xac, 0x77, 0x66, 0xf3, 0x19, 0xfa, 0xdc, 0x21, 0x28, 0xd1, 0x29, 0x41, 0x57, 0x5c, 0x00, 0x6e]),
        bytearray([0xd0, 0x14, 0xf9, 0xa8, 0xc9, 0xee, 0x25, 0x89, 0xe1, 0x3f, 0x0c, 0xc8, 0xb6, 0x63, 0x0c, 0xa6])
    ]

    plaintext = bytearray([0x5c, 0xf6, 0xee, 0x79, 0x2c, 0xdf, 0x05, 0xe1, 0xba, 0x2b, 0x63, 0x25, 0xc4, 0x1a, 0x5f, 0x10])
    ciphertext = encipher(plaintext, keys)
    print(' '.join('{:02x}'.format(x) for x in ciphertext))
    p = decipher(ciphertext, keys)
    print(' '.join('{:02x}'.format(x) for x in p))
    print()

    plaintext = bytearray([0xa1, 0xf8, 0xd4, 0x88, 0x68, 0xc3, 0x52, 0x7c, 0xbe, 0x63, 0xc5, 0x23, 0xa3, 0x09, 0x27, 0x41])
    ciphertext = encipher(plaintext, keys)
    print(' '.join('{:02x}'.format(x) for x in ciphertext))
    p = decipher(ciphertext, keys)
    print(' '.join('{:02x}'.format(x) for x in p))