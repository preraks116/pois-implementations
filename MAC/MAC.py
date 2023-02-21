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
        tag = bin_r
        for i in range(d):
            bin_i = decimalToBinary(i+1).zfill(n_dash)
            
            block = message[i*(n_dash):(i+1)*(n_dash)]
            
            x = binaryToDecimal(bin_r + bin_d + bin_i + block)

            t_i = self.prf.evaluate(x)
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

        r = tag[:n_dash]

        tag_prime = self.mac(message, binaryToDecimal(r))
        
        return (tag == tag_prime)


# n, p, g, s = 16, 499, 145, 179
# message = "100001011111"
# r = 13
# tag = "1101000000000000000000000000000000000000000000000000"

# n, p, g, s = 12, 107, 39, 120
# message = "110101"
# r = 2
# tag = "010111101010000000001100101"

n, p, g, s = 20, 137, 45, 87
message = "010011001000110"
r = 7
tag = "00111110100000000111010001100010110101110100110000011101000000001"


mac = MAC(n, p, g, s)
print(mac.mac(message, r) == tag)
print(mac.vrfy(message, tag))