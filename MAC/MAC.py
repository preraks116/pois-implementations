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
        self.n_dash = security_parameter // 4

    def mac(self, message: str, random_identifier: int) -> str:
        """
        Generate tag t
        :param random_identifier: r
        :type random_identifier: int
        :param message: message encoded as bit-string
        :type message: str
        """
        num_blocks = len(message) // (self.n_dash)
        d, r = Convert.toBinary(len(message) // (self.n_dash)).zfill(self.n_dash), Convert.toBinary(random_identifier).zfill(self.n_dash)
        t = ""
        for i in range(0, num_blocks):
            bin_i, block = Convert.toBinary(i+1).zfill(self.n_dash), message[i*(self.n_dash):(i+1)*(self.n_dash)]
            t_i = self.prf.evaluate(Convert.toDecimal(r + d + bin_i + block))
            t += Convert.toBinary(t_i).zfill(self.security_parameter)
        return r + t

    def vrfy(self, message: str, tag: str) -> bool:
        """
        Verify whether the tag commits to the message
        :param message: m
        :type message: str
        :param tag: t
        :type tag: str
        """
        random_seed = tag[:self.n_dash]
        return (tag == self.mac(message, Convert.toDecimal(random_seed)))


if "__main__" == __name__:
    n, p, g, s, r = 28, 617, 150, 123, 2
    mac = "111011101100101001110"
    message = "0000010100010001000100010001000100011110000010011011000100010001111000001001101100010001000"
    x = MAC(n, p, g, s)
    print(MAC(n,p,g,s).vrfy(message, x.mac(message, r)))