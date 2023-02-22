import sys 
import os
curdir = os.path.dirname(os.path.abspath(__file__))
relative_path = os.path.join(curdir, '../PRG')
sys.path.append(relative_path)
from PRG import PRG
from PRG import *

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
        self.prg = PRG(security_parameter, generator, prime_field, expansion_factor)

    def enc(self, message: str) -> str:
        """
        Encrypt Message against Eavesdropper Adversary
        :param message: message encoded as bit-string
        :type message: str
        """
        # Here the encryption scheme is One Time Pad using PRG
        
        # get the prg output on the key
        prg_output = self.prg.generate(self.key)
        new_key = int(prg_output, 2)

        # convert string to int
        m = int(message, 2) 

        # getting the encrypted message by XORing the message with the key
        e = m ^ new_key

        # convert the encrypted message to binary and zero padding 
        enc_message = decimalToBinary(e).zfill(self.security_parameter)
        # zfill just in case 
        return enc_message


    def dec(self, cipher: str) -> str:
        """
        Decipher ciphertext
        :param cipher: ciphertext encoded as bit-string
        :type cipher: str
        """
        # get the prg output on the key
        prg_output = self.prg.generate(self.key)
        
        # converting key to binary
        new_key = int(prg_output, 2)

        cipher_text = int(cipher, 2)

        # getting the decrypted message by XORing the cipher text with the key
        d = cipher_text ^ new_key

        # convert the decrypted message to binary
        dec_message = str(decimalToBinary(d))

        return dec_message