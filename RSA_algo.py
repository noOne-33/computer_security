import random

def gcd(a, b):
    """
    Euclid's algorithm for determining the greatest common divisor.
    """
    while b != 0:
        a, b = b, a % b
    return a

def multiplicative_inverse(e, phi):
    """
    Extended Euclidean Algorithm to find the modular multiplicative inverse of e under modulo phi.
    Returns d such that (d * e) % phi == 1
    """
    d = 0
    x1 = 0
    x2 = 1
    y1 = 1
    temp_phi = phi
    
    while e > 0:
        temp1 = temp_phi // e
        temp2 = temp_phi - temp1 * e
        temp_phi = e
        e = temp2
        
        x = x2 - temp1 * x1
        y = d - temp1 * y1
        
        x2 = x1
        x1 = x
        d = y1
        y1 = y
    
    if temp_phi == 1:
        return d + phi

def generate_keypair(p, q):
    """
    Generates the public and private keys based on two prime numbers.
    """
    if p == q:
        raise ValueError("p and q cannot be equal")
    
    # 1. Compute n
    n = p * q
    
    # 2. Compute phi(n)
    phi = (p - 1) * (q - 1)
    
    # 3. Choose an integer e such that 1 < e < phi and gcd(e, phi) = 1
    e = random.randrange(1, phi)
    
    # Use Euclid's Algorithm to verify that e and phi are coprime
    g = gcd(e, phi)
    while g != 1:
        e = random.randrange(1, phi)
        g = gcd(e, phi)
        
    # 4. Compute d (Modular Inverse)
    d = multiplicative_inverse(e, phi)
    
    # Return ((Public Key), (Private Key))
    # Public Key: (e, n)
    # Private Key: (d, n)
    return ((e, n), (d, n))

def encrypt(pk, plaintext):
    """
    Encrypts a string plaintext using the public key (pk).
    """
    key, n = pk
    # Convert each letter in the plaintext to numbers based on the character using a^b mod m
    # pow(char, key, n) is Python's efficient modular exponentiation
    cipher = [pow(ord(char), key, n) for char in plaintext]
    return cipher

def decrypt(pk, ciphertext):
    """
    Decrypts a list of integers using the private key (pk).
    """
    key, n = pk
    # Generate the plaintext based on the ciphertext and key using a^b mod m
    plain = [chr(pow(char, key, n)) for char in ciphertext]
    return ''.join(plain)

# --- usage example ---

if __name__ == '__main__':
    print("RSA Encrypter/ Decrypter")
    
    # 1. Select Primes
    # In a real scenario, these would be massive random primes.
    # For this example, we use small primes.
    p = 61
    q = 53
    
    print(f"Generating Keypair with primes: p={p}, q={q}")
    public, private = generate_keypair(p, q)
    
    print(f"Public Key: {public}")
    print(f"Private Key: {private}")
    
    # 2. Message to Encrypt
    message = "Hello WorlD!"
    print(f"\nOriginal Message: {message}")
    
    # 3. Encryption
    encrypted_msg = encrypt(public, message)
    print(f"Encrypted Message: {encrypted_msg}")
    
    # 4. Decryption
    decrypted_msg = decrypt(private, encrypted_msg)
    print(f"Decrypted Message: {decrypted_msg}")