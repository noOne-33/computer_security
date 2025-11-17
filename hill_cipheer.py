import numpy as np

def create_key_matrix(key_string, n):
    """
    Creates an n x n key matrix from a string.
    Checks if the key is valid for the given matrix size.
    """
    if len(key_string) != n * n:
        raise ValueError(f"Key string must be {n*n} characters long for a {n}x{n} matrix.")
    
    key = [ord(char.upper()) - ord('A') for char in key_string]
    key_matrix = np.array(key).reshape(n, n)
    return key_matrix

def modular_inverse(a, m):
    """Finds the modular multiplicative inverse of a under modulo m."""
    for i in range(1, m):
        if (a * i) % m == 1:
            return i
    return None # No modular inverse exists

def matrix_mod_inverse(matrix, modulus):
    """
    Finds the modular inverse of a matrix.
    The matrix must be square and its determinant must be coprime to the modulus.
    """
    # Calculate the determinant
    det = int(np.round(np.linalg.det(matrix))) % modulus
    
    # Find the modular inverse of the determinant
    det_inv = modular_inverse(det, modulus)
    
    if det_inv is None:
        raise ValueError("Matrix is not invertible (determinant has no modular inverse).")
        
    # Calculate the adjugate matrix (using the formula: adj(A) = det(A) * inv(A))
    # NumPy's inv() returns floats, so we round and convert to int
    adjugate = np.round(np.linalg.det(matrix) * np.linalg.inv(matrix)).astype(int)
    
    # The modular inverse is (det_inv * adjugate) mod modulus
    inverse_matrix = (det_inv * adjugate) % modulus
    
    return inverse_matrix

def hill_cipher(text, key_matrix, mode):
    """
    Encrypts or decrypts text using the Hill cipher.

    Args:
        text (str): The input string.
        key_matrix (np.array): The n x n NumPy key matrix.
        mode (str): 'encrypt' or 'decrypt'.
    """
    n = key_matrix.shape[0]
    modulus = 26
    
    # Determine the matrix to use (key or its inverse)
    if mode == 'encrypt':
        matrix_to_use = key_matrix
    elif mode == 'decrypt':
        matrix_to_use = matrix_mod_inverse(key_matrix, modulus)
    else:
        raise ValueError("Mode must be 'encrypt' or 'decrypt'.")
        
    # Prepare the text
    text = ''.join(filter(str.isalpha, text)).upper()
    
    # Pad the text if its length is not a multiple of n
    if len(text) % n != 0:
        padding_needed = n - (len(text) % n)
        text += 'X' * padding_needed
        
    result = ""
    
    # Process the text in blocks of size n
    for i in range(0, len(text), n):
        block = text[i:i+n]
        # Convert block of letters to a column vector of numbers
        block_vector = np.array([ord(char) - ord('A') for char in block]).reshape(n, 1)
        
        # Perform matrix multiplication
        result_vector = np.dot(matrix_to_use, block_vector) % modulus
        
        # Convert result vector back to letters and append to result
        for j in range(n):
            result += chr(result_vector[j][0] + ord('A'))
            
    return result

# --- Example Usage ---

# 1. Example with a 2x2 matrix
print("--- 2x2 Example ---")
key_str_2x2 = "DDFC"
plaintext_2x2 = "help me"
try:
    key_matrix_2x2 = create_key_matrix(key_str_2x2, 2)

    encrypted_text = hill_cipher(plaintext_2x2, key_matrix_2x2, 'encrypt')
    print(f"Plaintext:  {plaintext_2x2}")
    print(f"Key String: {key_str_2x2}")
    print(f"Encrypted:  {encrypted_text}")

    decrypted_text = hill_cipher(encrypted_text, key_matrix_2x2, 'decrypt')
    print(f"Decrypted:  {decrypted_text}")
except ValueError as e:
    print(f"Error: {e}")

print("\n" + "-"*20 + "\n")

# 2. Example with a 3x3 matrix (a classic example)
print("--- 3x3 Example ---")
key_str_3x3 = "GYBNQKURP" # A valid invertible key
plaintext_3x3 = "ACT"
try:
    key_matrix_3x3 = create_key_matrix(key_str_3x3, 3)

    encrypted_text_3x3 = hill_cipher(plaintext_3x3, key_matrix_3x3, 'encrypt')
    print(f"Plaintext:  {plaintext_3x3}")
    print(f"Key String: {key_str_3x3}")
    print(f"Encrypted:  {encrypted_text_3x3}")

    decrypted_text_3x3 = hill_cipher(encrypted_text_3x3, key_matrix_3x3, 'decrypt')
    print(f"Decrypted:  {decrypted_text_3x3}")
except ValueError as e:
    print(f"Error: {e}")
    
print("\n" + "-"*20 + "\n")

# 3. Example with a non-invertible key
print("--- Invalid Key Example ---")
key_str_invalid = "ABCD" # det=AD-BC = 3*0 - 1*2 = -2 mod 26 = 24. gcd(24,26) != 1
plaintext_invalid = "test"
try:
    key_matrix_invalid = create_key_matrix(key_str_invalid, 2)
    encrypted_invalid = hill_cipher(plaintext_invalid, key_matrix_invalid, 'encrypt')
    print(f"Encrypted with invalid key: {encrypted_invalid}")
    decrypted_invalid = hill_cipher(encrypted_invalid, key_matrix_invalid, 'decrypt')
except ValueError as e:
    print(f"Error during decryption: {e}")