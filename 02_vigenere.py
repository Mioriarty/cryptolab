import include.utils as utils
additiv = __import__("01_additiv")

def encipher(text: str, key: str) -> str:
    """
    Enciphers a 7-bit ASCII plaintext and a 7-bit ASCII key with the vigenère cipher.

    Args:
        text (str): 7-bit ASCII plaintext.
        key (str): 7-bit ASCII key.

    Returns:
        str: Ciphertext.
    """
    return "".join(chr((ord(c) + ord(key[i % len(key)])) % 128) for i, c in enumerate(text))

def decipher(text: str, key: str) -> str:
    """
    Deciphers a 7-bit ASCII ciphertext and a 7-bit ASCII key with the vigenère cipher.

    Args:
        text (str): 7-bit ASCII ciphertext
        key (str): 7-bit ASCII key

    Returns:
        str: Plaintext.
    """
    return "".join(chr((ord(c) - ord(key[i % len(key)]) + 128) % 128) for i, c in enumerate(text))

def determineBestKeyLength(text: str, minLength : int = 2, maxLength : int = 60) -> int:
    """
    Determines the most likely key length that was used when enciphering with the vigenère cipher.

    For each possible key length, it will compute the average of the index of coincidence of all possible coloumns of the key. The highest index will win.

    If there is a smaller length with an index almost as high, this smaller will be taken instead.

    Args:
        text (str): Ciphertext
        minLength (int, optional): Minimum key length. Defaults to 2.
        maxLength (int, optional): Maximum key length. Defaults to 60.

    Returns:
        int: The most likely key length that was used when enciphering with the vigenère cipher.
    """
    icValues = {}
    for keyLength in range(minLength, maxLength + 1):
        icTotal = 0
        for groupIndex in range(keyLength):
            charCounts = {}
            charNum = 0
            for i in range(groupIndex, len(text), keyLength):
                charNum += 1
                if text[i] in charCounts:
                    charCounts[text[i]] += 1
                else:
                    charCounts[text[i]] = 1

            icTotal += 1/(charNum * (charNum-1)) * sum([count * (count-1) for count in charCounts.values()])

        icValues[keyLength] = icTotal / keyLength

    bestKeyLength = max(icValues, key=icValues.get)

    # look for a smaller one that fits just as good
    EPSILON = 1e-3
    for i in range(minLength, bestKeyLength):
        if icValues[i] >= icValues[bestKeyLength] - EPSILON:
            return i
    
    # no better key length found
    return bestKeyLength

def determineKeyFromKeyLength(text : str, keyLength : int) -> str:
    """
    Given the ciphertext and the key length, it will compute the most likely key by using additive.determineBestKey coloumnwise.

    Args:
        text (str): 7-bit ASCII ciphertext
        keyLength (int): Length of the key used.

    Returns:
        str: _description_
    """
    return "".join(chr(additiv.determineBestKey(text[groupIndex::keyLength])) for groupIndex in range(keyLength))


if(__name__ == '__main__'):
    print("***** Vigenère Cipher *****")
    if(utils.yesNoQuestion("Du you want to encipher?")):
        text = utils.textFromFileOrConsole()
        key = input("Insert the key: ")

        print("Enciphered text:")
        print(encipher(text, key))


    else:
        text = utils.textFromFileOrConsole()
        
        if(utils.yesNoQuestion("Do you want to determine the key automatically?")):
            keyLength = determineBestKeyLength(text)
            print(f"Best key length {keyLength}")

            key = determineKeyFromKeyLength(text, keyLength)
            print(f"Best key: {key}")

            print("Deciphered text:")
            print(decipher(text, key))
        
        else:
            key = input("Insert the key: ")

            print(f"Deciphered text:")
            print(decipher(text, key))


