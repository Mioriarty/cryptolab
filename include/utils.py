from pathlib import Path

RES_FOLDER = Path("res/")

def yesNoQuestion(question: str) -> bool:
    answ = input(question + " (Y / N) ")
    return answ.lower()[0] == 'y'

def getFileContent(filename : str) -> str:
    with open(RES_FOLDER / filename, 'r') as f:
        return f.read()

def textFromFileOrConsole() -> str:
    if yesNoQuestion("Do you want to get the input from a file?"):
        return getFileContent(input("File Name: "))

    else:
        return input("Input your text: ")