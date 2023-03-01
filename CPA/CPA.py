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

class CPA:
    def __init__(self, security_parameter: int, prime_field: int,
                 generator: int, key: int, mode="CTR"):
        """
        Initialize the values here
        :param security_parameter: 1ⁿ
        :type security_parameter: int
        :param prime_field: q
        :type prime_field: int
        :param generator: g
        :type generator: int
        :param key: k
        :type key: int
        :param mode: Block-Cipher mode of operation
            - CTR
            - OFB
            - CBC
        :type mode: str
        """
        self.security_parameter = security_parameter
        self.prime_field = prime_field
        self.generator = generator
        self.key = key
        self.mode = mode
        self.PRF = PRF(security_parameter, generator, prime_field, key)

    def XOR_blocks(self, message: str, random_seed: int) -> str:
        """
        Evaluates the message in blocks of security parameter
        """
        output = ""
        for i in range(0, len(message), self.security_parameter):
            ctr = random_seed + 1 + (i)//self.security_parameter
            xor_block = Convert.XOR(Convert.toDecimal(message[i:i+self.security_parameter]), self.PRF.evaluate(ctr))
            output += Convert.toBinary(xor_block).zfill(self.security_parameter)
        return output

    def enc(self, message: str, random_seed: int) -> str:
        """
        Encrypt message against Chosen Plaintext Attack using randomized ctr mode
        :param message: m
        :type message: int
        :param random_seed: ctr
        :type random_seed: int
        """
        return Convert.toBinary(random_seed).zfill(self.security_parameter) + self.XOR_blocks(message, random_seed)

    def dec(self, cipher: str) -> str:
        """
        Decrypt ciphertext to obtain plaintext message
        :param cipher: ciphertext c
        :type cipher: str
        """
        random_seed, ciphertext = cipher[:self.security_parameter], cipher[self.security_parameter:]
        return self.blockEval(ciphertext, Convert.toDecimal(random_seed))

if "__main__" == __name__:
    enc = "01001100100011100100"
    print(CPA(4, 307, 112, 58).enc("1010100011100111", 4))
    print(enc)