from typing import Optional

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
        d = len(message) // n
        t = "0" * n

        for i in range(d):
            m = message[i*n:(i+1)*n]
            deci_t = binaryToDecimal(t)
            m = binaryToDecimal(m)
            t = self.prf_1.evaluate(deci_t ^ m)
            t = decimalToBinary(t)
    
        t_1 = t
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
        return (self.mac(message) == tag)

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