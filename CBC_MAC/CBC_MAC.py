import sys 
import os

curdir = os.path.dirname(os.path.abspath(__file__))

relative_path_1 = os.path.join(curdir, '../PRG')
sys.path.append(relative_path_1)

relative_path_2 = os.path.join(curdir, '../PRF')
sys.path.append(relative_path_2)


from PRG import PRG
from PRG import Convert
from PRF import PRF

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
        self.F_k_1 = PRF(security_parameter, generator, prime_field, keys[0])
        self.F_k_2 = PRF(security_parameter, generator, prime_field, keys[1])

    def mac(self, message: str) -> int:
        """
        Message Authentication code for message
        :param message: message encoded as bit-string m
        :type message: str
        """
        t_1 = "0" * self.security_parameter
        for i in range(len(message) // self.security_parameter):
            block = Convert.toDecimal(message[i*self.security_parameter:(i+1)*self.security_parameter])
            xor_block = Convert.XOR(Convert.toDecimal(t_1), block)
            t_1 = Convert.toBinary(self.F_k_1.evaluate(xor_block))    
        return self.F_k_2.evaluate(Convert.toDecimal(t_1))

    def vrfy(self, message: str, tag: int) -> bool:
        """
        Verify if the tag commits to the message
        :param message: m
        :type message: str
        :param tag: t
        :type tag: int
        """
        return self.mac(message) == tag