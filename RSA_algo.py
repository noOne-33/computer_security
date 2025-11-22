import random

def gcd(a, b):
    while b != 0:
        a, b = b, a % b
    return a

def generate_keypair(p, q):
    if p == q:
        raise ValueError("p and q cannot be equal")
    
    n = p * q
    phi = (p - 1) * (q - 1)
    
    # Choose e such that gcd(e, phi) = 1
    e = random.randrange(1, phi)
    while gcd(e, phi) != 1:
        e = random.randrange(1, phi)
    
    # Built-in modular inverse: d = e⁻¹ mod phi
    d = pow(e, -1, phi)
    
    return ((e, n), (d, n))

def encrypt(pk, plaintext):
    key, n = pk
    return [pow(ord(char), key, n) for char in plaintext]

def decrypt(pk, ciphertext):
    key, n = pk
    return ''.join(chr(pow(char, key, n)) for char in ciphertext)

# --- usage example ---
if __name__ == '__main__':
    print("RSA Encrypter/ Decrypter")
    
    p = 61
    q = 53
    
    print(f"Generating Keypair with primes: p={p}, q={q}")
    public, private = generate_keypair(p, q)
    
    print(f"Public Key: {public}")
    print(f"Private Key: {private}")
    
    message = "Hello WorlD!"
    print(f"\nOriginal Message: {message}")
    
    encrypted_msg = encrypt(public, message)
    print(f"Encrypted Message: {encrypted_msg}")
    
    decrypted_msg = decrypt(private, encrypted_msg)
    print(f"Decrypted Message: {decrypted_msg}")
