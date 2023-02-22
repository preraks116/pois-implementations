import sys 
import os

curdir = os.path.dirname(os.path.abspath(__file__))

relative_path_1 = os.path.join(curdir, '../PRG')
sys.path.append(relative_path_1)

relative_path_2 = os.path.join(curdir, '../PRF')
sys.path.append(relative_path_2)


from PRG import PRG
from PRG import *
from PRF import PRF
from PRF import *

class CBC_MAC:
    def __init__(self, security_parameter: int, generator: int,
                 prime_field: int, keys: list[int]):
        """
        Initialize the values here
        :param security_parameter: 1ⁿ
        :type security_parameter: int
        :param generator: g
        :type generator: int
        :param prime_field: q
        :type prime_field: int
        :param keys: k₁, k₂
        :type keys: list[int]
        """
        self.security_parameter = security_parameter
        self.generator = generator
        self.prime_field = prime_field
        self.keys = keys
        self.prf_1 = PRF(security_parameter, generator, prime_field, keys[0])
        self.prf_2 = PRF(security_parameter, generator, prime_field, keys[1])

    def mac(self, message: str) -> int:
        """
        Message Authentication code for message
        :param message: message encoded as bit-string m
        :type message: str
        """
        n = self.security_parameter
        # step 1 : compute basic CBC-MAC t_1 using k_1 

        # set initial t to be a string of n 0's
        d = len(message) // n
        
        t = "0" * n

        for i in range(d):
            # get the i-th block of message
            m = message[i*n:(i+1)*n]
            # convert t and m to decimal
            deci_t = binaryToDecimal(t)
            m = binaryToDecimal(m)
            # compute t = F_k1(t xor m)
            t = self.prf_1.evaluate(deci_t ^ m)
            # convert t to binary
            t = decimalToBinary(t)
    
        t_1 = t
        # step 2 : compute output MAC tag t = F_k2(t_1)
        t = self.prf_2.evaluate(binaryToDecimal(t_1))

        return t

    def vrfy(self, message: str, tag: int) -> bool:
        """
        Verify if the tag commits to the message
        :param message: m
        :type message: str
        :param tag: t
        :type tag: int
        """
        return self.mac(message) == tag


if __name__ == "__main__":

    # n, g, p, k1, k2 = 4, 35, 97, 14, 12
    # message = "1010100101111"

    # n, g, p, k1, k2 = 4, 144, 719, 11, 8
    # message = "11011101011000111000"

    # n, g, p, k1, k2 = 4, 67, 461, 5, 6
    # message = "11100111"

    n, g, p, k1, k2 = 4, 113, 227, 2, 7
    message = "111010100101"

    keys = [k1, k2]
    cbc_mac = CBC_MAC(n, g, p, keys)

    tag = cbc_mac.mac(message)
    print("Tag: ", tag)