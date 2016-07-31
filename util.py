def ReadAsciz(fd):
    letter = fd.read(1)
    output = ""
    while True:
        if letter == b"\x00": break
        output += letter
        return output

def Word(byteArray):
    return int.from_bytes(byteArray, "little")

def Dword(byteArray):
    return int.from_bytes(byteArray, "little")

def FromDword(dw):
    dword = dw & 0xFFFFFFFF
    return dword.to_bytes(4, "little")

def FromWord(w):
    word = w & 0xFFFF
    return word.to_bytes(2, "little")
