import copy

class Matrix:

    def __init__(self, height = 0, width = 0, values = []):
        self.vals = []
        self.width = width
        self.height = height
        self.zero = 0

        for i in range(height*width):
            self.vals.append(values[i % len(values)])

    
    def __setitem__(self, pos, val):
        y, x = pos
        if y >= self.height or x >= self.width:
            raise IndexError()
        self.vals[y * self.width + x] = val

    def __getitem__(self, pos):
        y, x = pos
        if y >= self.height or x >= self.width:
            raise IndexError()
        return self.vals[y * self.width + x]

    def __add__(self, other):
        if not(self.height == other.height and self.width == other.width):
            raise ValueError("Dimensions don't match!")
        
        return Matrix(self.height, self.width, [a+b for (a, b) in tuple(zip(self.vals, other.vals))])
    
    def __sub__(self, other):
        if not(self.height == other.height and self.width == other.width):
            raise ValueError("Dimensions don't match!")
        
        return Matrix(self.height, self.width, [a-b for (a, b) in tuple(zip(self.vals, other.vals))])
    
    def __mul__(self, other):
        if isinstance(other, Matrix):
            if(self.width != other.height):
                 raise ValueError("Dimensions don't match!")
            
            newVals = []
            for y in range(self.height):
                for x in range(other.width):
                    v = copy.copy(self.zero)
                    for i in range(other.height):
                        v += self[y, i] * other[i, x]
                    newVals.append(v)
            return Matrix(self.height, other.width, newVals)
        else:
            return Matrix(self.height, self.width, [other * v for v in self.vals])

    def setRow(self, rowNum , vals):
        if rowNum >= self.height:
            raise IndexError()
        for i in range(self.width):
            self[rowNum, i] = vals[i % len(vals)]
    
    def setCol(self, colNum , vals):
        if colNum >= self.width:
            raise IndexError()
        for i in range(self.height):
            self[i, colNum] = vals[i % len(vals)]

    def getRow(self, rowNum):
        if rowNum >= self.height:
            raise IndexError()
        return [self[rowNum, i] for i in range(self.width)]
    
    def getCol(self, colNum):
        if colNum >= self.width:
            raise IndexError()
        return [self[i, colNum] for i in range(self.height)]
    

    def __str__(self):
        maxLengths = [max([len(str(v)) for v in self.getCol(i)]) for i in range(self.width)]
        stm = "/ "

        for y in range(self.height):
            for x in range(self.width):
                stm += str(self[y, x]) + " "*(maxLengths[x]-len(str(self[y, x])) + 2)
            stm = stm[:-1]
            if y == 0:
                stm += "\\"
            else:
                stm += "|"
            stm += "\n"
            if y == self.height - 2:
                stm += "\\ "
            else:
                stm += "| "

        stm = stm[:-4] + "/"
        return stm

    def useAsZero(self, zero):
        self.zero = zero