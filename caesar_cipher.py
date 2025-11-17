def caesar_cipher(text, shift, mode):
   
    # The alphabet we will use for shifting
    alphabet = 'abcdefghijklmnopqrstuvwxyz'
    result = ''

    shift = shift % 26

    # For decryption, we reverse the shift
    if mode == 'decrypt':
        shift = -shift

    for char in text:
        # Check if the character is an alphabet letter
        if char.lower() in alphabet:

            position = alphabet.find(char.lower())
            
            new_position = (position + shift) % 26
            
            new_char = alphabet[new_position]
            
            # Maintain the original case (uppercase or lowercase)
            if char.isupper():
                result += new_char.upper()
            else:
                result += new_char
        else:
            # If the character is not a letter, keep it as is
            result += char
            
    return result

# --- Example Usage ---

# 1. Define the message and the key (shift)
original_message = "Hello, World! This is a secret message."
cipher_key = 7

# 2. Encrypt the message
encrypted_message = caesar_cipher(original_message, cipher_key, 'encrypt')
print(f"Original Message:  {original_message}")
print(f"Encrypted Message: {encrypted_message}")

# 3. Decrypt the message
decrypted_message = caesar_cipher(encrypted_message, cipher_key, 'decrypt')
print(f"Decrypted Message: {decrypted_message}")
