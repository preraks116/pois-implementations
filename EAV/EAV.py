import sys 
import os
curdir = os.path.dirname(os.path.abspath(__file__))
relative_path = os.path.join(curdir, '../PRG')
sys.path.append(relative_path)

from PRG import PRG
from PRG import Convert

class Eavesdrop:
    def __init__(self, security_parameter: int, key: int, expansion_factor: int,
                 generator: int, prime_field: int):
        """
        Initialize values here
        :param security_parameter: 1ⁿ
        :type security_parameter: int
        :param key: k, uniformly sampled key
        :type key: int
        :param expansion_factor: l(n)
        :type expansion_factor: int
        :param generator: g
        :type generator: int
        :param prime_field: p
        :type prime_field: int
        """
        self.security_parameter = security_parameter
        self.key = key
        self.expansion_factor = expansion_factor
        self.generator = generator
        self.prime_field = prime_field
        self.PRG = PRG(security_parameter, generator, prime_field, expansion_factor)
        self.G_k = Convert.toDecimal(self.PRG.generate(self.key))

    def enc(self, message: str) -> str:
        """
        Encrypt Message against Eavesdropper Adversary
        :param message: message encoded as bit-string
        :type message: str
        """
        return Convert.toBinary(Convert.XOR(Convert.toDecimal(message), self.G_k))


    def dec(self, cipher: str) -> str:
        """
        Decipher ciphertext
        :param cipher: ciphertext encoded as bit-string
        :type cipher: str
        """
        return str(Convert.toBinary(Convert.XOR(Convert.toDecimal(cipher), self.G_k)))

if "__main__" == __name__:
    message = "1000101"
    enc = "1100101"
    print(Eavesdrop(7, 16, 7, 21, 59).enc(message))   
    print(enc)