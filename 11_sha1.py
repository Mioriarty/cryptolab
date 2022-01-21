# Hauptsächich für __add__, __invert__ und __lshift__
class int32:

    MAX = 1 << 32

    def __init__(self, val : int | bytearray = 0):
        if isinstance(val, int):
            self.val = val  % int32.MAX
        elif isinstance(val, bytearray):
            self.val = int.from_bytes(val, byteorder='big') % int32.MAX
        else:
            raise TypeError("Cration of int32 must happen with int or bytearray")
    

    def __add__(self, o : 'int32') -> 'int32':
        return int32(self.val + o.val)
    
    def __and__(self, o : 'int32') -> 'int32':
        return int32(self.val & o.val)

    def __or__(self, o : 'int32') -> 'int32':
        return int32(self.val | o.val)

    def __xor__(self, o : 'int32') -> 'int32':
        return int32(self.val ^ o.val)

    def __invert__(self) -> 'int32':
        return int32(int32.MAX - self.val - 1)
    
    def __lshift__(self, amount : int) -> 'int32':
        # cyclic left shift
        leftMask = self.val >> (32 - amount)
        return int32((self.val << amount) | leftMask)
    
    def __str__(self) -> str:
        return "{:32b}".format(self.val)
    


def addPadding(message : bytearray) -> bytearray:
    mL = 8 * len(message)

    numPadding = (120 - ((len(message) + 1) % 64)) % 64
    return message + bytearray([ 0x80 ] + [ 0 ] * numPadding) + mL.to_bytes(8, byteorder='big')


def sha1(message : str) -> int:
    message = addPadding(bytearray(message, 'UTF-8'))

    h0 = int32(0x67452301)
    h1 = int32(0xEFCDAB89)
    h2 = int32(0x98BADCFE)
    h3 = int32(0x10325476)
    h4 = int32(0xC3D2E1F0)

    # split the message into blocks
    blocks = [ message[64*i : 64*(i+1)] for i in range(len(message) // 64)]

    for block in blocks:
        # split one block into words
        words = [ int32(block[4*i : 4*(i+1)]) for i in range(16)]
        
        # extends the word list
        for i in range(16, 80):
            words.append((words[i-3] ^ words[i-8] ^ words[i-14] ^ words[i-16]) << 1)
        
        # initialize the variables
        a, b, c, d, e = h0, h1, h2, h3, h4


        # do the crazy sha-1 stuff
        for i in range(80):
            if i <= 19:
                f = (b & c) | ((~b) & d)
                k = int32(0x5A827999)
            elif 20 <= i <= 39:
                f = b ^ c ^ d
                k = int32(0x6ED9EBA1)
            elif 40 <= i <= 59:
                f = (b & c) | (b & d) | (c & d)
                k = int32(0x8F1BBCDC)
            else:
                f = b ^ c ^ d
                k = int32(0xCA62C1D6)
            
            tmp = (a << 5) + f + e + k + words[i]
            a, b, c, d, e = tmp, a, b << 30, c, d
        
        h0 += a
        h1 += b
        h2 += c
        h3 += d
        h4 += e
    

    return (h0.val << (32*4)) + (h1.val << (32*3)) + (h2.val << (32*2)) + (h3.val << (32*1)) + h4.val
    

print(hex(sha1("")))