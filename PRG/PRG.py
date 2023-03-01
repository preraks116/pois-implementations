class Convert:
    def toBinary(n: int):
        """
        Convert a decimal number to binary
        :param n: decimal number
        :type n: int
        """
        return bin(n)[2:]

    def toDecimal(n: str):
        """
        Convert a binary number to decimal
        :param n: binary number
        :type n: str
        """
        return int(n, 2)
    def XOR(a: int, b: int):
        """
        XOR two numbers
        :param a: first number
        :type a: int
        :param b: second number
        :type b: int
        """
        return a ^ b

class PRG:
    def __init__(self, security_parameter: int, generator: int,
                 prime_field: int, expansion_factor: int):
        """
        Initialize values here
        :param security_parameter: n (from 1ⁿ)
        :type security_parameter: int
        :param generator: g
        :type generator: int
        :param prime_field: p
        :type prime_field: int
        :param expansion_factor: l(n)
        :type expansion_factor: int
        """
        self.security_parameter = security_parameter
        self.generator = generator
        self.prime_field = prime_field
        self.expansion_factor = expansion_factor

    def owf(self, g: int, x: int, p: int) -> int:
        """
        One-way function: Discrete Logarithm Problem
        :param g: generator
        :type g: int
        :param x: input
        :type x: int
        :param p: prime field
        :type p: int
        """
        return pow(g, x, p)

    def hcp(self, num: int, p: int) -> int:
        """
        Hard Core Predicate
        """
        return (0 if num < (p-1)/2 else 1)

    def generate(self, seed: int) -> str:
        """
        Generate the pseudo-random bit-string from `seed`
        :param seed: uniformly sampled seed
        :type seed: int
        """
        randomBits = ""
        x = seed 
        for i in range(self.expansion_factor):
            randomBits += str(self.hcp(x, self.prime_field))
            x = self.owf(self.generator, x, self.prime_field)
        return randomBits

if "__main__" == __name__:
    enc = "101101000011000101101000011000101"
    print(PRG(12,11,29,33).generate(1058))
    print(enc)