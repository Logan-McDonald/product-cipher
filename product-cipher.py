def string_to_16bit_block(plaintext):
    return int.from_bytes(plaintext.encode(), 'big')

def substitute(block, key):
    return ((block >> key) | (block << (16 - key))) & 0xFFFF

def transpose(block):
    return ((block & 0x00FF) << 8) | ((block & 0xFF00) >> 8)

def encrypt(block, key):
    ciphertext = transpose(substitute(block, key))
    return ciphertext

def decrypt(ciphertext, key):
    block = ((ciphertext & 0x00FF) << 8) | ((ciphertext & 0xFF00) >> 8)
    return ((block >> (16 - key)) | (block << key)) & 0xFFFF

def calcDiff(val1, val2):
    # Convert inputs to binary strings of fixed length
    bin1 = f'{val1:016b}'
    bin2 = f'{val2:016b}'
    
    differences = 0
    for i in range(len(bin1)):
        if bin1[i] != bin2[i]:
            differences += 1
    
    return differences

def main():
    plaintext1 = "Hello"
    plaintext2 = "Helli"
    
    key = 5 
    block1 = string_to_16bit_block(plaintext1)
    print(f"Original first 16-bit block: {block1:016b}")
    
    # block2 = string_to_16bit_block(plaintext2)
    # print(f"Original second 16-bit block: {block2:016b}")

    encrypted_block = encrypt(block1, key)
    print(f"Encrypted 16-bit block: {encrypted_block:016b}")

    decrypted_block = decrypt(encrypted_block, key)
    print(f"Decrypted 16-bit block: {decrypted_block:016b}")
    
    print(f'Number of different bits: {calcDiff(block1, decrypted_block)}')

if __name__ == "__main__":
    main()