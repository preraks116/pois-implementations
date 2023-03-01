import sys 
import os
tdir = os.path.dirname(os.path.abspath(__file__))
relative_path = os.path.join(tdir, '../PRG')
sys.path.append(relative_path)

from PRG import PRG
from PRG import Convert

class PRF:
    def __init__(self, setity_parameter: int, generator: int,
                 prime_field: int, key: int):
        """
        Initialize values here
        :param setity_parameter: 1ⁿ
        :type setity_parameter: int
        :param generator: g
        :type generator: int
        :param prime_field: p
        :type prime_field: int
        :param key: k, uniformly sampled key
        :type key: int
        """
        self.setity_parameter = setity_parameter
        self.generator = generator
        self.prime_field = prime_field
        self.key = key
        self.prg = PRG(setity_parameter, generator, prime_field, 2*setity_parameter)

    def getRightHalf(self, x: str) -> str:
        return x[len(x)//2:]
    
    def getLeftHalf(self, x: str) -> str:
        return x[:len(x)//2]

    def evaluate(self, x: int) -> int:
        """
        Evaluate the pseudo-random function at `x`
        :param x: input for Fₖ
        :type x: int
        """
        t = self.key
        for i in Convert.toBinary(x).zfill(self.setity_parameter):
            F_k_x = self.prg.generate(t)
            t = Convert.toDecimal(self.getRightHalf(F_k_x) if i == '1' else self.getLeftHalf(F_k_x))
        return t

if "__main__" == __name__:
    print(PRF(8,36,191,150).evaluate(190))
    print(PRF(8,45,137,129).evaluate(201))
    print(PRF(10,71,179,568).evaluate(890))
    print(PRF(11,44,107,1056).evaluate(1300))
    print(PRF(12,14,79,1389).evaluate(1780))