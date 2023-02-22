import sys 
import os
from typing import Optional

curdir = os.path.dirname(os.path.abspath(__file__))

relative_path_1 = os.path.join(curdir, '../PRG')
sys.path.append(relative_path_1)

relative_path_2 = os.path.join(curdir, '../PRF')
sys.path.append(relative_path_2)

relative_path_3 = os.path.join(curdir, '../CPA')
sys.path.append(relative_path_3)

relative_path_4 = os.path.join(curdir, '../CBC_MAC')
sys.path.append(relative_path_4)

from PRG import PRG
from PRG import *
from PRF import PRF
from PRF import *
from CPA import CPA
from CPA import *
from CBC_MAC import CBC_MAC
from CBC_MAC import *

class CCA:
    def __init__(self, security_parameter: int, prime_field: int,
                 generator: int, key_cpa: int, key_mac: list[int],
                 cpa_mode="CTR"):
        """
        Initialize the values here
        :param security_parameter: 1ⁿ
        :type security_parameter: int
        :param prime_field: q
        :type prime_field: int
        :param generator: g
        :type generator: int
        :param key_cpa: k1
        :type key_cpa: int
        :param key_mac: k2
        :type key_mac: list[int]
        :param cpa_mode: Block-Cipher mode of operation for CPA
            - CTR
            - OFB
            - CBC
        :type cpa_mode: str
        """
        self.security_parameter = security_parameter
        self.prime_field = prime_field
        self.generator = generator
        self.key_cpa = key_cpa
        self.key_mac = key_mac
        self.cpa_mode = cpa_mode
        self.cpa = CPA(security_parameter, prime_field, generator, key_cpa)
        self.cbc_mac = CBC_MAC(security_parameter, generator, prime_field, key_mac)

    def enc(self, message: str, cpa_random_seed: int) -> str:
        """
        Encrypt message against Chosen Ciphertext Attack
        :param message: m
        :type message: str
        :param cpa_random_seed: random seed for CPA encryption
        :type cpa_random_seed: int
        """
        
        # encrypt the message using cpa_random_seed
        enc_message = self.cpa.enc(message, cpa_random_seed)

        # compute the mac of the encrypted message
        tag = self.cbc_mac.mac(enc_message)

        # convert the tag to binary to append at the end
        bin_tag = decimalToBinary(tag).zfill(self.security_parameter)

        return enc_message + bin_tag

    def dec(self, cipher: str) -> Optional[str]:
        """
        Decrypt ciphertext to obtain message
        :param cipher: <c, t>
        :type cipher: str
        """
        # separate the cipher and tag
        enc_message, bin_tag = cipher[:-self.security_parameter], cipher[-self.security_parameter:]
        tag = binaryToDecimal(bin_tag)
        
        # verify the tag
        if self.cbc_mac.vrfy(enc_message, tag):
            # decrypt the message
            message = self.cpa.dec(enc_message)
            return message
        else:
            return None


# n, p, g, key_cpa, key_mac_1, key_mac_2, cpa_random_seed = 7, 41, 17, 34, 10, 9, 12
# message = "101110101011101000011"
# enc = "00011001101101110010110000101111011"

# n, p, g, key_cpa, key_mac_1, key_mac_2, cpa_random_seed = 9, 149, 45, 41, 11, 23, 10
# message = "010011110000100110101110001100000010010000111"
# enc = "000001010010011110010000000010011110100110010010000111000000000"

n, p, g, key_cpa, key_mac_1, key_mac_2, cpa_random_seed = 6, 17, 7, 5, 17, 3, 18
message = "000101001000110010100110000000010100"
enc = "010010101000111101001011001011011110101010111100"

mac_keys = [key_mac_1, key_mac_2]
cca = CCA(n, p, g, key_cpa, mac_keys)

print(cca.enc(message, cpa_random_seed) == enc)
print(cca.dec(enc) == message)