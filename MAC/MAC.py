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

class MAC:
    def __init__(self, security_parameter: int, prime_field: int,
                 generator: int, seed: int):
        """
        Initialize the values here
        :param security_parameter: 1ⁿ
        :type security_parameter: int
        :param prime_field: q
        :type prime_field: int
        :param generator: g
        :type generator: int
        :param seed: k
        :type seed: int
        """
        self.security_parameter = security_parameter
        self.prime_field = prime_field
        self.generator = generator
        self.seed = seed
        self.prf = PRF(security_parameter, generator, prime_field, seed)

    def mac(self, message: str, random_identifier: int) -> str:
        """
        Generate tag t
        :param random_identifier: r
        :type random_identifier: int
        :param message: message encoded as bit-string
        :type message: str
        """
        n_dash = self.security_parameter//4

        d = len(message) // (n_dash)

        bin_d = decimalToBinary(d).zfill(n_dash)
        bin_r = decimalToBinary(random_identifier).zfill(n_dash)

        # for i = 1 to d, compute the t_i = F_k( r || d || i || m_i ) where || denotes concatenation
        t = []
        for i in range(d):
            bin_i = decimalToBinary(i+1).zfill(n_dash)
            # getting the message block
            block = message[i*(n_dash):(i+1)*(n_dash)]

            x = binaryToDecimal(bin_r + bin_d + bin_i + block)
            # calculating t_i
            t_i = self.prf.evaluate(x)

            # appending t_i to the list of tags
            t.append(t_i)

        # concatenate r and all the t_i's to form t 
        tag = bin_r + ''.join([decimalToBinary(i).zfill(self.security_parameter) for i in t])
        return tag



    def vrfy(self, message: str, tag: str) -> bool:
        """
        Verify whether the tag commits to the message
        :param message: m
        :type message: str
        :param tag: t
        :type tag: str
        """
        pass
        n_dash = self.security_parameter//4

        # extract random seed from the tag
        r = tag[:n_dash]

        # getting the tag of the input message with the same random seed
        tag_prime = self.mac(message, binaryToDecimal(r))
        
        # if the tags are same return true else return false
        return (tag == tag_prime)