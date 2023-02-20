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
        # print("bit_x is", bit_x)
        # print("-----")
        for i in bit_x:
            # print("i is", i)
            bin_cur = self.prg.generate(cur)
            # print("bin cur is", bin_cur)
            if i == '0':
                # left 
                y = left_half(bin_cur)
                #cur = binaryToDecimal(y)
                # print("y is", y)
            else: 
                # right
                y = right_half(bin_cur)
                #cur = binaryToDecimal(y)
                # print("y is", y)
            cur = binaryToDecimal(y)
            # print("-----")
        return cur

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