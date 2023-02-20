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

def toInt(num):
    num = str(num)
    ans = 0
    for i in num:
        ans = (ans << 1) + int(i)
    return ans

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
        # get the prg output on the key
        prg_output = self.prg.generate(self.key)
        new_key = int(prg_output, 2)

        # convert string to int
        m = int(message, 2) 

        e = m ^ new_key
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
        new_key = int(prg_output, 2)

        cipher_text = int(cipher, 2)

        d = cipher_text ^ new_key
        dec_message = str(decimalToBinary(d))

        return dec_message

# message = "1000101"
# n, k, l, g, p = 7, 16, 7, 21, 59
message = "10101001"
n, k, l, g, p = 8, 156, 8, 71, 599
eav = Eavesdrop(n,k,l,g,p)
print(eav.dec(eav.enc(message)) == message)