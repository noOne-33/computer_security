def vigenere_cipher(text, key, mode):
    # Sanitize the key: remove non-alphabetic characters and convert to lowercase
    key = ''.join(filter(str.isalpha, key)).lower()
    if not key:
        raise ValueError("The key must contain at least one alphabetic character.")

    result = []
    key_index = 0
    alphabet = 'abcdefghijklmnopqrstuvwxyz'
    
    for char in text:
        if char.isalpha():
            # Determine the shift amount from the key
            key_char = key[key_index % len(key)]
            shift = alphabet.find(key_char)

            # In decrypt mode, we reverse the shift
            if mode == 'decrypt':
                shift = -shift
            
            # Find the position of the character in the alphabet
            char_pos = alphabet.find(char.lower())
            
            # Calculate the new position
            new_pos = (char_pos + shift) % 26
            new_char = alphabet[new_pos]
            
            if char.isupper():
                result.append(new_char.upper())
            else:
                result.append(new_char)
            
            key_index += 1
        else:
            # If the character is not a letter, keep it as is
            result.append(char)
            
    return "".join(result)


plaintext1 = "ATTACKATDAWN"
keyword1 = "LEMON"

encrypted1 = vigenere_cipher(plaintext1, keyword1, 'encrypt')
print(f"Plaintext:  {plaintext1}")
print(f"Keyword:    {keyword1}")
print(f"Encrypted:  {encrypted1}")

decrypted1 = vigenere_cipher(encrypted1, keyword1, 'decrypt')
print(f"Decrypted:  {decrypted1}")

print("\n" + "-"*30 + "\n")

# 2. A more complex example with mixed case and punctuation
plaintext2 = "Cryptography is an interesting, if not always practical, subject!"
keyword2 = "SecretKey123" # The '123' will be filtered out

print(f"Plaintext:  {plaintext2}")
print(f"Keyword:    {keyword2} (sanitized to 'secretkey')")

encrypted2 = vigenere_cipher(plaintext2, keyword2, 'encrypt')
print(f"Encrypted:  {encrypted2}")

decrypted2 = vigenere_cipher(encrypted2, keyword2, 'decrypt')
print(f"Decrypted:  {decrypted2}")