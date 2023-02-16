# Function to convert decimal to binary 
def decimalToBinary(n):
    return bin(n)[2:]

# Function to convert binary to decimal
def binaryToDecimal(binary):
    return int(binary, 2)

# One way function : DLP
def dlp(g: int, x: int, p: int) -> int:
    return pow(g, x, p)

# Hard core predicate : MSB
def msb(num):
    return str(num)[0]

def hcp(num,p):
    if num>p/2:
        return 1
    else:
        return 0 


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

    def generate(self, seed: int) -> str:
        """
        Generate the pseudo-random bit-string from `seed`
        :param seed: uniformly sampled seed
        :type seed: int
        """
        extras = ""
        cur = seed 
        for i in range(self.expansion_factor):
            # calculate hcp of cur and store in extras 
            h = hcp(cur, self.prime_field)
            # print("hcp at i = ", i, " is ", h)
            extras += str(h)
            # print("extras at i = ", i, " is ", extras)
            # calculate one way function of cur and store in cur
            cur = dlp(self.generator, cur, self.prime_field)
            # print("cur at i = ", i, " is ", cur, decimalToBinary(cur))
            # print("------------------")
        # final output would be cur concatenated with extras
        output = str(decimalToBinary(cur).zfill(self.security_parameter)) + extras
        return output

print(PRG(2, 2, 5, 5).generate(2))
        