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

# check once ##########
def toInt(num):
    num = str(num)
    ans = 0
    for i in num:
        ans = (ans << 1) + int(i)
    return ans
#######################

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
            h = hcp(cur, self.prime_field)
            extras += str(h)
            cur = dlp(self.generator, cur, self.prime_field)

        output = str(decimalToBinary(cur).zfill(self.security_parameter)) + extras
        return output

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
        # print("prg_output is ", prg_output)
        # print("new_key is ", new_key)

        # convert message to binary
        # m = int(message, 2)
        string = ''.join(format(x, 'b') for x in bytearray(message, 'utf-8'))
        # convert string to int
        m = int(string, 2) 
        # store length of message in l

        l = len(string)
        # print("l is ", l)

        ##############################
        self.expansion_factor = l
        ##############################

        # print("string is ", string)
        # print("m is ", m)

        enc_message = m ^ new_key
        # print("enc_message is ", enc_message)
        return decimalToBinary(enc_message).zfill(self.security_parameter)

    def dec(self, cipher: str) -> str:
        """
        Decipher ciphertext
        :param cipher: ciphertext encoded as bit-string
        :type cipher: str
        """
        # get the prg output on the key
        prg_output = self.prg.generate(self.key)
        new_key = int(prg_output, 2)
        # print("prg_output is ", prg_output)
        # print("new_key is ", new_key)

        cipher_text = int(cipher, 2)
        # print("cipher_text is ", cipher_text)

        d = str(decimalToBinary(cipher_text ^ new_key))
        # print("dec_message is ", d)

        u = [d[i:i+7] for i in range(0,len(d), 7)]
        dec_message = ''.join(chr(toInt(int(x))) for x in u)

        return dec_message



# Expansion factor - is set while encryption
# If the message has spaces then scheme breaks
eav = Eavesdrop(2, 2, 0, 2, 5)
message = "canthandlespaces"
enc = eav.enc(message)
dec = eav.dec(enc)
print(dec)