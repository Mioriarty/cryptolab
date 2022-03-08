import include.utils as utils

def encipher(text: str, key: int) -> str:
    """
    Enciphers a 7-bit ASCII plaintext with the additive cipher.

    Args:
        text (str): 7-bit ASCII plaintext
        key (int): Key to be used. Should be between 0 und 127

    Returns:
        str: Ciphertext.
    """
    return "".join([ chr((ord(c) + key) % 128) for c in text ])


def decipher(text: str, key: int) -> str:
    """
    Deciphers a 7-bit ASCII ciphertext with the additive cipher.

    Args:
        text (str): 7-bit ASCII ciphertext
        key (int): Key to be used. Should be between 0 und 127

    Returns:
        str: Plaintext.
    """
    return "".join([ chr((ord(c) - key + 128) % 128) for c in text ])


def determineBestKey(text: str) -> int:
    """
    Determines the most likely key that was used when enciphering with the additive cipher.

    It will seek the most common letter and output its ASCII value difference to 32 (a space in ASCII) as a space is the most commen letter in a text.

    Args:
        text (str): The ciphertext.

    Returns:
        int: The most likely key that was used when enciphering with the additive cipher.
    """
    # count character appearances
    charCounts = {}
    for c in text:
        if c in charCounts:
            charCounts[c] += 1
        else:
            charCounts[c] = 1
    
    mostCommonChar = ord(max(charCounts, key=charCounts.get)) # shoud be a space (32 in ascii)
    return (mostCommonChar - 32 + 128) % 128


if(__name__ == '__main__'):
    print("***** Additive Cipher *****")
    if(utils.yesNoQuestion("Du you want to encipher?")):
        text = utils.textFromFileOrConsole()
        key = int(input("Insert the key: "))

        print("Enciphered text:")
        print(encipher(text, key))


    else:
        text = utils.textFromFileOrConsole()
        
        if(utils.yesNoQuestion("Do you want to determine the key automatically?")):
            key = determineBestKey(text)

            print(f"Deciphered text (Key: {key}):")
            print(decipher(text, key))
        
        else:
            key = int(input("Insert the key: "))

            print(f"Deciphered text:")
            print(decipher(text, key))


