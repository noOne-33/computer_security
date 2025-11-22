class AES:
    def __init__(self, key):
        # AES-128 requires a 16-byte key
        if len(key) != 16:
            raise ValueError("Key must be exactly 16 bytes long for AES-128")
        
        # The S-Box (Substitution Box)
        # A pre-computed lookup table used for non-linearity.
        self.s_box = [
            0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
            0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
            0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
            0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
            0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
            0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
            0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
            0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
            0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
            0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
            0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
            0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
            0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
            0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
            0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
            0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16
        ]

        # R-Con (Round Constants) used in Key Expansion
        self.r_con = [
            0x00, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36
        ]

        self.round_keys = self.key_expansion(key)

    # --- Step 1: Key Expansion ---
    def key_expansion(self, key):
        # AES-128 uses 4 words (columns) for the original key
        # and generates 40 more words for 10 rounds.
        key_columns = [list(key[i:i+4]) for i in range(0, len(key), 4)]
        
        i = 4
        while i < 44: # 4 cols * (10 rounds + 1 initial) = 44 columns
            temp = key_columns[i-1][:] # Copy previous word
            
            if i % 4 == 0:
                # Rotate word: [a,b,c,d] -> [b,c,d,a]
                temp = temp[1:] + temp[:1]
                # Substitute word using S-Box
                temp = [self.s_box[b] for b in temp]
                # XOR with R-Con
                temp[0] ^= self.r_con[i // 4]
                
            # XOR with the word 4 positions back
            prev = key_columns[i-4]
            new_word = [temp[k] ^ prev[k] for k in range(4)]
            key_columns.append(new_word)
            i += 1
            
        return key_columns

    # --- Step 2: SubBytes ---
    # Substitute every byte in the state with one from the S-Box
    def sub_bytes(self, state):
        for r in range(4):
            for c in range(4):
                state[r][c] = self.s_box[state[r][c]]
        return state

    # --- Step 3: ShiftRows ---
    # Row 0: No shift
    # Row 1: Shift left 1
    # Row 2: Shift left 2
    # Row 3: Shift left 3
    def shift_rows(self, state):
        state[1] = state[1][1:] + state[1][:1]
        state[2] = state[2][2:] + state[2][:2]
        state[3] = state[3][3:] + state[3][:3]
        return state

    # --- Step 4: MixColumns ---
    # This is the most math-heavy part. It uses Galois Field (GF) multiplication.
    def gmul(self, a, b):
        # Galois Field multiplication of a and b in GF(2^8)
        p = 0
        for _ in range(8):
            if b & 1:
                p ^= a
            hi_bit_set = a & 0x80
            a = (a << 1) & 0xFF
            if hi_bit_set:
                a ^= 0x1b # The irreducible polynomial for AES
            b >>= 1
        return p

    def mix_columns(self, state):
        # Matrix multiplication with a fixed matrix over GF(2^8)
        # Fixed Matrix:
        # 2 3 1 1
        # 1 2 3 1
        # 1 1 2 3
        # 3 1 1 2
        for c in range(4):
            col = [state[r][c] for r in range(4)]
            state[0][c] = self.gmul(col[0], 2) ^ self.gmul(col[1], 3) ^ col[2] ^ col[3]
            state[1][c] = col[0] ^ self.gmul(col[1], 2) ^ self.gmul(col[2], 3) ^ col[3]
            state[2][c] = col[0] ^ col[1] ^ self.gmul(col[2], 2) ^ self.gmul(col[3], 3)
            state[3][c] = self.gmul(col[0], 3) ^ col[1] ^ col[2] ^ self.gmul(col[3], 2)
        return state

    # --- Step 5: AddRoundKey ---
    # Simple XOR of the state with the current round's key
    def add_round_key(self, state, round_idx):
        for c in range(4):
            # Select the specific column from the expanded keys
            key_col = self.round_keys[round_idx * 4 + c]
            for r in range(4):
                state[r][c] ^= key_col[r]
        return state

    # --- Main Encryption Function ---
    def encrypt_block(self, plaintext):
        if len(plaintext) != 16:
            raise ValueError("Input block must be exactly 16 bytes")

        # Convert input bytes to a 4x4 state matrix (column-major order)
        # AES standard fills columns first:
        # Byte 0 -> [0][0], Byte 1 -> [1][0], Byte 2 -> [2][0], etc.
        state = [[0] * 4 for _ in range(4)]
        for r in range(4):
            for c in range(4):
                state[r][c] = plaintext[r + 4 * c]

        # 1. Initial AddRoundKey
        self.add_round_key(state, 0)

        # 2. Main Rounds (1 to 9)
        for round_idx in range(1, 10):
            self.sub_bytes(state)
            self.shift_rows(state)
            self.mix_columns(state)
            self.add_round_key(state, round_idx)

        # 3. Final Round (No MixColumns)
        self.sub_bytes(state)
        self.shift_rows(state)
        self.add_round_key(state, 10)

        # Convert state matrix back to bytes (column-major)
        encrypted_bytes = []
        for c in range(4):
            for r in range(4):
                encrypted_bytes.append(state[r][c])
        
        return bytes(encrypted_bytes)

# =========================================
# Usage Example
# =========================================

# 1. Define a 16-byte Key (128 bits)
key = b'Thats my Kung Fu' # Exactly 16 chars

# 2. Initialize AES with the key
aes = AES(key)

# 3. Define a 16-byte block to encrypt
# (In real life, you need Padding if the message isn't exactly 16 bytes)
plaintext = b'Two One Nine Two'

print(f"Plaintext: {plaintext}")
print(f"Key:       {key}")

# 4. Encrypt
ciphertext = aes.encrypt_block(plaintext)
print(f"Encrypted: {ciphertext.hex()}")

# Expected output for this specific Key/Plaintext combination (Standard Test Vector):
# Encrypted: 29c3505f571420f6402299b31a02d73a