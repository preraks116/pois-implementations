from PRG.PRG import *

# key k is chosen and then fixed 
# key, input and output will be of same length
# mapping from n-bit strings to n-bit strings 

# function which, given a string of 2n bits, returns the left n bits
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

    def evaluate(self, x: int) -> int:
        """
        Evaluate the pseudo-random function at `x`
        :param x: input for Fₖ
        :type x: int
        """
        cur = self.key
        bit_x = decimalToBinary(x).zfill(self.security_parameter)
        for i in bit_x:
            print("i is", i)
            cur = dlp(self.generator, cur, self.prime_field)
            bin_cur = decimalToBinary(cur)
            print("cur is", cur, "binary = ", bin_cur)
            if i == '0':
                # left 
                y = left_half(bin_cur)
                cur = binaryToDecimal(y)
                print("y is", y)
            else: 
                # right
                y = right_half(bin_cur)
                cur = binaryToDecimal(y)
                print("y is", y)
            print("-----")
        return decimalToBinary(cur).zfill(self.security_parameter)

# print(PRF(2,2,5,3).evaluate(3))