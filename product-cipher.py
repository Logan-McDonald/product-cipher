import numpy as np

# S-box functions
SBOX = [
    0x3, 0xF, 0xE, 0x1, 0xD, 0x8, 0xB, 0x6,
    0x4, 0xA, 0x7, 0xC, 0x2, 0x9, 0x5, 0x0
]

def apply_sbox(byte):
    high_nibble = (byte >> 4) & 0xF
    low_nibble = byte & 0xF
    return (SBOX[high_nibble] << 4) | SBOX[low_nibble]

# Apply S-box substitution to each byte in the 16-bit block
def substitute(block):
    high_byte = apply_sbox((block >> 8) & 0xFF)
    low_byte = apply_sbox(block & 0xFF)
    return (high_byte << 8) | low_byte

# Bit-level permutation for diffusion
def transpose(block):
    permuted = 0
    permutation = [0, 4, 8, 12, 1, 5, 9, 13, 2, 6, 10, 14, 3, 7, 11, 15]
    for i in range(16):
        bit = (block >> i) & 1
        permuted |= (bit << permutation[i])
    return permuted

# Encrypt a 16-bit block using substitution and transposition
def encrypt_block(block, rounds=4):
    state = block
    for _ in range(rounds):
        state = substitute(state)
        state = transpose(state)
    return state

# Decrypt a 16-bit block
def decrypt_block(block, rounds=4):
    inverse_sbox = [SBOX.index(i) for i in range(16)]
    
    def inverse_sbox_substitution(byte):
        high_nibble = (byte >> 4) & 0xF
        low_nibble = byte & 0xF
        return (inverse_sbox[high_nibble] << 4) | inverse_sbox[low_nibble]

    state = block
    for _ in range(rounds):
        state = transpose(state)
        high_byte = inverse_sbox_substitution((state >> 8) & 0xFF)
        low_byte = inverse_sbox_substitution(state & 0xFF)
        state = (high_byte << 8) | low_byte
    return state

# Convert string to list of 16-bit blocks
def string_to_blocks(text):
    if len(text) % 2 != 0:
        text += " "
    
    blocks = [int.from_bytes(text[i:i+2].encode(), 'big') for i in range(0, len(text), 2)]
    return blocks

# Compute the SAC for a given plaintext block
def calculate_SAC(block, rounds=4):
    original_ciphertext = encrypt_block(block, rounds)
    bit_changes = []

    for i in range(16):
        modified_block = block ^ (1 << i)
        modified_ciphertext = encrypt_block(modified_block, rounds)
        
        bit_diff = bin(original_ciphertext ^ modified_ciphertext).count('1')
        bit_changes.append(bit_diff)

    average_flip = (sum(bit_changes) / (16 * 16)) * 100
    return average_flip

# Compute the BIC for a given plaintext block.
def calculate_BIC(block, rounds=4):
    flipped_ciphertexts = []

    for i in range(16):
        modified_block = block ^ (1 << i)
        modified_ciphertext = encrypt_block(modified_block, rounds)
        flipped_ciphertexts.append(modified_ciphertext)
        
    flipped_matrix = np.array([[int(b) for b in f'{ct:016b}'] for ct in flipped_ciphertexts])
    correlation_matrix = np.corrcoef(flipped_matrix.T) 

    n = correlation_matrix.shape[0]
    avg_correlation = (np.sum(np.abs(correlation_matrix)) - n) / (n * (n - 1))

    return avg_correlation

def main():
    plaintext = "Hi"
    
    # Convert text to 16-bit blocks
    blocks = string_to_blocks(plaintext)
    print(f"Original Block(s): {[bin(b) for b in blocks]}")
    
    # Encrypt
    encrypted_blocks = [encrypt_block(b) for b in blocks]
    print(f"Encrypted Block(s): {[bin(b) for b in encrypted_blocks]}")
    
    # Decrypt
    decrypted_blocks = [decrypt_block(b) for b in encrypted_blocks]
    print(f"Decrypted Block(s): {[bin(b) for b in decrypted_blocks]}")
    
    # Calculate SAC
    for block in blocks:
        sac = calculate_SAC(block)
        print(f"SAC for block {bin(block)}: {sac:.2f}%")
        
    # Calculate BIC
    for block in blocks:
        bic = calculate_BIC(block)
        print(f"BIC for block {bin(block)}: {bic:.4f} (Ideal: ~0)")

if __name__ == "__main__":
    main()