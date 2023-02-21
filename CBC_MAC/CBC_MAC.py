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
    if num < (p-1)/2:
        return 0
    else:
        return 1 

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
            cur = dlp(self.generator, cur, self.prime_field)
            h = hcp(seed, self.prime_field)
            seed = cur
            extras += str(h)
        return extras

def left_half(x: str) -> str:
    return x[:len(x)//2]

def right_half(x: str) -> str:
    return x[len(x)//2:]

class PRF:
    def __init__(self, security_parameter: int, generator: int,
                 prime_field: int, key: int):
        """
        Initialize values here
        :param security_parameter: 1ⁿ
        :type security_parameter: int
        :param generator: g
        :type generator: int
        :param prime_field: p
        :type prime_field: int
        :param key: k, uniformly sampled key
        :type key: int
        """
        self.security_parameter = security_parameter
        self.generator = generator
        self.prime_field = prime_field
        self.key = key
        self.prg = PRG(security_parameter, generator, prime_field, 2*security_parameter)

    def evaluate(self, x: int) -> int:
        """
        Evaluate the pseudo-random function at `x`
        :param x: input for Fₖ
        :type x: int
        """
        cur = self.key
        bit_x = decimalToBinary(x).zfill(self.security_parameter)
        for i in bit_x:
            bin_cur = self.prg.generate(cur)
            if i == '0':
                y = left_half(bin_cur)
            else: 
                y = right_half(bin_cur)
            cur = binaryToDecimal(y)
        return cur

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
        self.prf_1 = PRF(security_parameter, generator, prime_field, keys[0])
        self.prf_2 = PRF(security_parameter, generator, prime_field, keys[1])

    def mac(self, message: str) -> int:
        """
        Message Authentication code for message
        :param message: message encoded as bit-string m
        :type message: str
        """
        n = self.security_parameter
        # step 1 : compute basic CBC-MAC t_1 using k_1 

        # set initial t to be a string of n 0's
        d = len(message) // n
        
        t = "0" * n

        for i in range(d):
            # get the i-th block of message
            m = message[i*n:(i+1)*n]
            # convert t and m to decimal
            deci_t = binaryToDecimal(t)
            m = binaryToDecimal(m)
            # compute t = F_k1(t xor m)
            t = self.prf_1.evaluate(deci_t ^ m)
            # convert t to binary
            t = decimalToBinary(t)
    
        t_1 = t
        # step 2 : compute output MAC tag t = F_k2(t_1)
        t = self.prf_2.evaluate(binaryToDecimal(t_1))

        return t

    def vrfy(self, message: str, tag: int) -> bool:
        """
        Verify if the tag commits to the message
        :param message: m
        :type message: str
        :param tag: t
        :type tag: int
        """
        return self.mac(message) == tag

# n, g, p, k1, k2 = 4, 35, 97, 14, 12
# message = "1010100101111"

# n, g, p, k1, k2 = 4, 144, 719, 11, 8
# message = "11011101011000111000"

# n, g, p, k1, k2 = 4, 67, 461, 5, 6
# message = "11100111"

n, g, p, k1, k2 = 4, 113, 227, 2, 7
message = "111010100101"

keys = [k1, k2]
cbc_mac = CBC_MAC(n, g, p, keys)

tag = cbc_mac.mac(message)
print("Tag: ", tag)