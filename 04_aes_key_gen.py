aes = __import__("03_aes")

class Word:
    """
    Represents a word in the AES key gen algorithm.
    """

    def __init__(self, value : bytearray):
        """
        Constrcutor of the Word class.

        Args:
            value (bytearray): The value of the word. Should be 4 bytes.
        """
        self.val = value
    
    def sub(self) -> 'Word':
        """
        Substitutes the bytes using the AES Sbox.

        Returns:
            Word: The new Word with substituted bytes.
        """
        return Word(bytearray(aes.SBOX[b] for b in self.val))
    
    def rot(self) -> 'Word':
        """
        Rotates all bytes in the word by 1.

        Returns:
            Word: The new Word with rotated bytes.
        """
        return Word(bytearray([self.val[(i+1) % 4] for i in range(4)]))
    
    def __xor__(self, other : 'Word') -> 'Word':
        """
        Xors 2 words bytewise.

        Args:
            other (Word): The other word to be xored.

        Returns:
            Word: The new xored word.
        """
        return Word(bytearray(self.val[i] ^ other.val[i] for i in range(4)))

    @classmethod
    def rcon(cls, i : int) -> 'Word':
        """
        Generates constant words by an index.

        The formula is: rcon(i) = Word(rc_i, 0, 0, 0) with rc_i = x^(i-1) in GF(2^8)

        Args:
            i (int): The index of that word.

        Returns:
            Word: Constant words by the specified index.
        """
        RC = [ 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36 ]
        return cls(bytearray([ RC[i-1], 0, 0, 0 ]))
    
def genKeys(key : bytearray) -> list[bytearray]:
    """
    Generates 11 AES round keys (each 16 bytes) from a single 16 byte key.

    Args:
        key (bytearray): The single key (16 bytes) from which the round keys can be generated.

    Returns:
        list[bytearray]: 11 AES round keys, 16 bytes each.
    """

    # split key into words (these are the first words to use)
    words = [ Word(key[4*i : 4*(i+1)]) for i in range(4) ]

    for i in range(4, 44):
        if i % 4 == 0:
            words.append(words[i-4] ^ Word.rcon(i // 4) ^ words[i-1].rot().sub())
        else:
            words.append(words[i-4] ^ words[i-1])
    
    keys = [ words[i].val + words[i+1].val + words[i+2].val + words[i+3].val for i in range(0, 44, 4) ]
    return keys


def encipherECB(plaintext : str, key : bytearray) -> bytearray:
    """
    Enciphers a plaintext of any length using the electronic code block mode and the AES cipher.

    Args:
        plaintext (str): The plaintext. Should be UTF-8 encoded.
        key (bytearray): 1 AES key. With it the 11 round keys will be generated. Should be 16 bytes.

    Returns:
        bytearray: The ciphertext.
    """
    # split message in blocks and do padding
    plaintext = bytearray(plaintext, 'UTF-8') + bytearray(15) # add 15 zeros, that will get cut off
    plaintextBlocks = [plaintext[16*i : 16*(i+1)] for i in range(len(plaintext) // 16)]

    # generate keys and encrypt every block
    keys = genKeys(key)
    ciphertextBlocks = [ aes.encipher(block, keys) for block in plaintextBlocks ]
    
    # combine all ciphertext blocks
    ciphertext = bytearray()
    for block in ciphertextBlocks:
        ciphertext += block
    return ciphertext

def decipherECB(ciphertext : bytearray, key : bytearray) -> str:
    """
    Disiphers a ciphertext of any length using the electronic code block mode and the AES cipher.

    Args:
        plaintext (str): The ciphertext.
        key (bytearray): 1 AES key. With it the 11 round keys will be generated. Should be 16 bytes.

    Returns:
        bytearray: The plaintext. WIll be UTF-8 encoded.
    """
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
    key = bytearray("Das ist mein Key", "UTF-8")

    text = "Hallo ich hoffe du kommst Ende nachmal raus. Das heisst nähmlich, dass das was ich gemacht habe, gar nicht so schlecht ist :)"
    cipher = encipherECB(text, key)
    print(cipher)
    print(decipherECB(cipher, key))