def generate_key_table(key):
    # 1. Sanitize key: uppercase, replace J with I, remove non-alpha
    key = key.upper().replace('J', 'I')
    key = ''.join(filter(str.isalpha, key))

    seen = set()
    unique_key_letters = [char for char in key if not (char in seen or seen.add(char))]

    # 3. Create the initial sequence for the table
    alphabet = "ABCDEFGHIKLMNOPQRSTUVWXYZ" # No 'J'
    table_sequence = unique_key_letters + [char for char in alphabet if char not in unique_key_letters]

    # 4. Build the 5x5 table and the coordinate map
    table = [table_sequence[i:i+5] for i in range(0, 25, 5)]
    # Creates a mapping like {'A': (0, 2), 'B': (2, 0), ...} for O(1) lookups
    coords = {letter: (r, c) for r, row in enumerate(table) for c, letter in enumerate(row)}

    return table, coords

def prepare_plaintext(text, filler='X'):
    # 1. Sanitize text: uppercase, replace J with I, remove non-alpha
    text = text.upper().replace('J', 'I')
    text = ''.join(filter(str.isalpha, text))

    # 2. Handle double letters and create digraphs
    prepared_text = []
    i = 0
    while i < len(text):
        char1 = text[i]
        # If at the end of the string, append filler and break
        if i + 1 == len(text):
            prepared_text.append(char1 + filler)
            break
        
        char2 = text[i+1]
        
        if char1 == char2:
            prepared_text.append(char1 + filler)
            i += 1 # Move one step forward
        else:
            prepared_text.append(char1 + char2)
            i += 2 # Move two steps forward
            
    return prepared_text

def playfair_cipher(text, key, mode):
    """
    Encrypts or decrypts text using the Playfair cipher.

    Args:
        text (str): The input string to be processed.
        key (str): The keyword for the cipher.
        mode (str): 'encrypt' or 'decrypt'.
    
    Returns:
        str: The processed (encrypted or decrypted) string.
    """
    if mode not in ['encrypt', 'decrypt']:
        raise ValueError("Mode must be 'encrypt' or 'decrypt'.")

    table, coords = generate_key_table(key)
    digraphs = prepare_plaintext(text)
    result = []

    # Set direction for shift (1 for encrypt, -1 for decrypt)
    direction = 1 if mode == 'encrypt' else -1

    for d in digraphs:
        p1, p2 = d[0], d[1]
        row1, col1 = coords[p1]
        row2, col2 = coords[p2]

        if row1 == row2: # Case 1: Same row
            new_col1 = (col1 + direction) % 5
            new_col2 = (col2 + direction) % 5
            result.append(table[row1][new_col1])
            result.append(table[row1][new_col2])
        elif col1 == col2: # Case 2: Same column
            new_row1 = (row1 + direction) % 5
            new_row2 = (row2 + direction) % 5
            result.append(table[new_row1][col1])
            result.append(table[new_row2][col2])
        else: # Case 3: Rectangle
            # The rule is the same for encrypt and decrypt
            result.append(table[row1][col2])
            result.append(table[row2][col1])
            
    return "".join(result)


# --- Example Usage ---

# 1. Define message and key
key = "PLAYFAIR EXAMPLE"
plaintext = "Hide the gold in the tree stump"

# 2. Encrypt
encrypted_text = playfair_cipher(plaintext, key, 'encrypt')
print(f"Plaintext:  {plaintext}")
print(f"Keyword:    {key}")
print(f"Encrypted:  {encrypted_text}")

# 3. Decrypt
decrypted_text = playfair_cipher(encrypted_text, key, 'decrypt')
print(f"Decrypted:  {decrypted_text}") 
# Note: The decrypted text will be uppercase, without spaces, J->I, and with filler 'X's.
# This is an inherent property of the classic Playfair cipher.