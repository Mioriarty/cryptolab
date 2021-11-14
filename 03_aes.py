from include.matrix import Matrix
import include.utils as utils

class GaloisElement:
    def __init__(self, val):
        self.val = val

    def double(self):
        self.val = self.val << 1

        if self.val & 0b100000000:
            self.val = self.val ^ 0b100011011

    
    def __add__(self, other):
        return GaloisElement(bytes([self.val])[0] ^ bytes([other.val])[0])
    
    def __mul__(self, other):
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
    global SBOX, SBOX_INV
    SBOX =  [ int(k, 16) for k in utils.getFileContent("03_SBox.txt").replace("\n", " ").split(", ") ]
    SBOX_INV = [ int(k, 16) for k in utils.getFileContent("03_SBoxInvers.txt").replace("\n", " ").split(", ") ]

def matToGalois(x : Matrix) -> Matrix:
    return Matrix(x.height, x.width, [ GaloisElement(e) for e in x.vals ]) 

# *********** ENCIPHER *************

def encipher(plaintext : bytearray, keys : list[bytearray]) -> bytearray:
    x = Matrix(4, 4, plaintext)
    addRoundKey(x, keys[0])
    
    for i in range(1, 10):
        subBytes(x)
        shiftRows(x)
        mixColums(x)
        addRoundKey(x, keys[i])
    
    subBytes(x)
    shiftRows(x)
    addRoundKey(x, keys[10])

    return bytes(x.vals)

def addRoundKey(x : Matrix, key : bytearray) -> None:
    x.vals = list(bytes(a ^ b for (a, b) in zip(x.vals, key)))

def subBytes(x : Matrix) -> None:
    for i in range(16):
        x.vals[i] = SBOX[x.vals[i]]

def shiftRows(x : Matrix) -> None:
    cpy = Matrix(4, 4, x.vals[:])
    for i in range(1, 4):
        for j in range(4):
            x[i, (j + i) % 4] = cpy[i, j]

def mixColums(x : Matrix) -> None:
    FACTOR = matToGalois(Matrix(4, 4, [
        2, 3, 1, 1,
        1, 2, 3, 1,
        1, 1, 2, 3,
        3, 1, 1, 2
    ]))
    FACTOR.useAsZero(GaloisElement(0))

    for col in range(4):
        newCol = FACTOR * matToGalois(Matrix(4, 1, x.getCol(col)))
        x.setCol(col, [ e.val for e in newCol.vals ])


# *************** DECIPHER ***************

def decipher(ciphertext : bytearray, keys : list[bytearray]):
    x = Matrix(4, 4, ciphertext)

    addRoundKey(x, keys[10])
    shiftRowsInv(x)
    subBytesInv(x)

    for i in range(9, 0, -1):
        addRoundKey(x, keys[i])
        mixColumsInv(x)
        shiftRowsInv(x)
        subBytesInv(x)
    
    addRoundKey(x, keys[0])

    return bytes(x.vals)


def subBytesInv(x : Matrix) -> None:
    for i in range(16):
        x.vals[i] = SBOX_INV[x.vals[i]]

def shiftRowsInv(x : Matrix) -> None:
    cpy = Matrix(4, 4, x.vals[:])
    for i in range(1, 4):
        for j in range(4):
            x[i, (j - i + 4) % 4] = cpy[i, j]

def mixColumsInv(x : Matrix) -> None:
    FACTOR = matToGalois(Matrix(4, 4, [
        0xE, 0xB, 0xD, 9,
        9, 0xE, 0xB, 0xD,
        0xD, 9, 0xE, 0xB,
        0xB, 0xD, 9, 0xE
    ]))
    FACTOR.useAsZero(GaloisElement(0))

    for col in range(4):
        newCol = FACTOR * matToGalois(Matrix(4, 1, x.getCol(col)))
        x.setCol(col, [ e.val for e in newCol.vals ])
        

loadSBoxes()


plaintext = bytearray("Hallo du Alter A", "UTF-8")
keys = [ bytearray("Balko ist cooler", "UTF-8"), bytearray("ubodubgsbjvbkncv", "UTF-8"), bytearray("45k5kh345kh5hk4b", "UTF-8"), bytearray("-xlcma-clmakccyc", "UTF-8"), bytearray("9778IHOD6%&/((SD", "UTF-8"), bytearray("9Hf37/&fjhcZhgh+", "UTF-8"), 
         bytearray("-#+xy676%&/gxchj", "UTF-8"), bytearray("!shd68asgn#+9jh4", "UTF-8"), bytearray("xycc.,mimim<a3ff", "UTF-8"), bytearray("sfsf<d8tgjghjjgg", "UTF-8"), bytearray("hoh)/)/GFGzibxcvl", "UTF-8") ]


print(plaintext)
ciphertext = encipher(plaintext, keys)
print(ciphertext)

print(decipher(ciphertext, keys))