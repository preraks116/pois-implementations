import sys 
import os
curdir = os.path.dirname(os.path.abspath(__file__))
relative_path = os.path.join(curdir, '../PRG')
sys.path.append(relative_path)
from PRG import PRG
from PRG import *

def left_half(x: str) -> str:
    return x[:len(x)//2]

def right_half(x: str) -> str:
    return x[len(x)//2:]

class PRF:
    def __init__(self, security_parameter: int, generator: int,
                 prime_field: int, key: int):
        """
        Initialize values here
        :param security_parameter: 1ⁿ
        :type security_parameter: int
        :param generator: g
        :type generator: int
        :param prime_field: p
        :type prime_field: int
        :param key: k, uniformly sampled key
        :type key: int
        """
        self.security_parameter = security_parameter
        self.generator = generator
        self.prime_field = prime_field
        self.key = key
        self.prg = PRG(security_parameter, generator, prime_field, 2*security_parameter)

    def evaluate(self, x: int) -> int:
        """
        Evaluate the pseudo-random function at `x`
        :param x: input for Fₖ
        :type x: int
        """
        cur = self.key
        bit_x = decimalToBinary(x).zfill(self.security_parameter)

        # iterating through the bits of x to compute the PRF
        for i in bit_x:
            bin_cur = self.prg.generate(cur)
            
            if i == '0':
                # left side of the binary string is taken 
                y = left_half(bin_cur)
            else: 
                # right side of the binary string is taken
                y = right_half(bin_cur)

            cur = binaryToDecimal(y)

        return cur