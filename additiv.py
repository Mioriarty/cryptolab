import include.utils as utils

def encipher(text: str, key: int) -> str:
    return "".join([ chr((ord(c) + key) % 128) for c in text ])


def decipher(text: str, key: int) -> str:
    return "".join([ chr((ord(c) - key + 128) % 128) for c in text ])


def determineBestKey(text: str) -> int:
    # count character appearances
    charCounts = {}
    for c in text:
        if c in charCounts:
            charCounts[c] += 1
        else:
            charCounts[c] = 1
    
    mostCommonChar = ord(max(charCounts, key=charCounts.get)) # shoud be a space (32 in ascii)
    return (mostCommonChar - 32 + 128) % 128



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


