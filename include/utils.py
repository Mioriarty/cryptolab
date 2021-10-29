from pathlib import Path

RES_FOLDER = Path("res/")

def yesNoQuestion(question: str) -> bool:
    answ = input(question + " (Y / N) ")
    return answ.lower()[0] == 'y'


def textFromFileOrConsole() -> str:
    if yesNoQuestion("Do you want to get the input from a file?"):
        path = RES_FOLDER / input("File Name: ")

        with open(path, 'r') as f:
            return f.read()
    
    else:
        return input("Input your text: ")