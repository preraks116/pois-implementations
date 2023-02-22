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
        self.prf = PRF(security_parameter, generator, prime_field, key)

    def blockEval(self, message: str, random_seed: int) -> str:
        output = ""
        for i in range(0, len(message), self.security_parameter):
            block = message[i:i+self.security_parameter]
            deci_block = binaryToDecimal(block)

            r_i = random_seed + 1 + (i)//self.security_parameter 
            prf_output = self.prf.evaluate(r_i)

            out = deci_block ^ prf_output

            enc_block = decimalToBinary(out).zfill(self.security_parameter)
            output += enc_block
        return output

    def enc(self, message: str, random_seed: int) -> str:
        """
        Encrypt message against Chosen Plaintext Attack using randomized ctr mode
        :param message: m
        :type message: int
        :param random_seed: ctr
        :type random_seed: int
        """
        # convert the random seed to binary 
        r = decimalToBinary(random_seed).zfill(self.security_parameter)

        enc_message = self.blockEval(message, random_seed)

        output = r + enc_message
        return output

    def dec(self, cipher: str) -> str:
        """
        Decrypt ciphertext to obtain plaintext message
        :param cipher: ciphertext c
        :type cipher: str
        """
        r = cipher[:self.security_parameter]
        enc_message = cipher[self.security_parameter:]

        # evaluating in blocks
        dec_message = self.blockEval(enc_message, binaryToDecimal(r))
        return dec_message

        
if __name__ == "__main__":
    # n, p, g, k = 4, 307, 112, 58
    # message = "1010100011100111"
    # enc = "01001100100011100100"
    # r = 4

    # n, p, g, k = 5, 599, 189, 145
    # message = "11100011011110010111"
    # # 851503
    # enc = "0011111001111111000101111"
    # r = 7

    n, p, g, k = 8, 11, 3, 15
    message = "1010100110110111"
    enc = "000010001000110110100101"
    r = 8

    cpa = CPA(n, p, g, k)

    print(cpa.enc(message, r) == enc)
    print(cpa.dec(enc) == message)