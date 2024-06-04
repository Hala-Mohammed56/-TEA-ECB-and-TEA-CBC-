import os

# padding function
def pad(data, block_size=8):
    padding_size = block_size - (len(data) % block_size)
    padding = bytes([padding_size] * padding_size)
    return data + padding

#unpadding function
def unpad(padded_data, block_size=8):
    padding_size = padded_data[-1]
    if padding_size < 1 or padding_size > block_size:
        raise ValueError("Invalid padding")
    if padded_data[-padding_size:] != bytes([padding_size] * padding_size):
        raise ValueError("Invalid padding")
    return padded_data[:-padding_size]


# TEA encryption function
def TeaEncrypt(block, key):
    Delta = 0x9E3779B9
    Sum = 0
    RoundsNum = 32
    v0, v1 = block

    for _ in range(RoundsNum):
        Sum = (Sum + Delta) & 0xFFFFFFFF
        v0 = (v0 + (((v1 << 4) + key[0]) ^ (v1 + Sum) ^ ((v1 >> 5) + key[1]))) & 0xFFFFFFFF
        v1 = (v1 + (((v0 << 4) + key[2]) ^ (v0 + Sum) ^ ((v0 >> 5) + key[3]))) & 0xFFFFFFFF

    return v0, v1


# TEA decryption function
def TeaDecrypt(block, key):
    Delta = 0x9E3779B9
    Sum = (Delta * 32) & 0xFFFFFFFF
    RoundsNum = 32
    v0, v1 = block

    for _ in range(RoundsNum):
        v1 = (v1 - (((v0 << 4) + key[2]) ^ (v0 + Sum) ^ ((v0 >> 5) + key[3]))) & 0xFFFFFFFF
        v0 = (v0 - (((v1 << 4) + key[0]) ^ (v1 + Sum) ^ ((v1 >> 5) + key[1]))) & 0xFFFFFFFF
        Sum = (Sum - Delta) & 0xFFFFFFFF

    return v0, v1


# ECB mode encryption with TEA and padding
def TeaEcbEncrypt(plaintext, key):
    padded_plaintext = pad(plaintext)
    encrypted_blocks = []

    for i in range(0, len(padded_plaintext), 8):
        block = padded_plaintext[i:i + 8]
        block_tuple = (int.from_bytes(block[:4], 'big'), int.from_bytes(block[4:], 'big'))
        encrypted_block = TeaEncrypt(block_tuple, key)
        encrypted_blocks.extend(encrypted_block)

    encrypted_data = b''.join([block_part.to_bytes(4, 'big') for block_part in encrypted_blocks])
    return encrypted_data


# ECB mode decryption with TEA and unpadding
def TeaEcbDecrypt(ciphertext, key):
    decrypted_blocks = []

    for i in range(0, len(ciphertext), 8):
        block = ciphertext[i:i + 8]
        block_tuple = (int.from_bytes(block[:4], 'big'), int.from_bytes(block[4:], 'big'))
        decrypted_block = TeaDecrypt(block_tuple, key)
        decrypted_blocks.extend(decrypted_block)

    decrypted_data = b''.join([block_part.to_bytes(4, 'big') for block_part in decrypted_blocks])
    unpadded_data = unpad(decrypted_data)
    return unpadded_data


# CBC mode encryption with TEA and padding
def TeaCbcEncrypt(plaintext, key, iv):
    padded_plaintext = pad(plaintext)
    encrypted_blocks = []
    previous_block = iv

    for i in range(0, len(padded_plaintext), 8):
        block = padded_plaintext[i:i + 8]
        block_int = (
        int.from_bytes(block[:4], 'big') ^ previous_block[0], int.from_bytes(block[4:], 'big') ^ previous_block[1])
        encrypted_block = TeaEncrypt(block_int, key)
        encrypted_blocks.extend(encrypted_block)
        previous_block = encrypted_block

    encrypted_data = b''.join([block_part.to_bytes(4, 'big') for block_part in encrypted_blocks])
    return encrypted_data


# CBC mode decryption with TEA and unpadding
def TeaCbcDecrypt(ciphertext, key, iv):
    decrypted_blocks = []
    previous_block = iv

    for i in range(0, len(ciphertext), 8):
        block = ciphertext[i:i + 8]
        encrypted_block_tuple = (int.from_bytes(block[:4], 'big'), int.from_bytes(block[4:], 'big'))
        decrypted_block = TeaDecrypt(encrypted_block_tuple, key)
        decrypted_block = (decrypted_block[0] ^ previous_block[0], decrypted_block[1] ^ previous_block[1])
        decrypted_blocks.extend(decrypted_block)
        previous_block = encrypted_block_tuple

    decrypted_data = b''.join([block_part.to_bytes(4, 'big') for block_part in decrypted_blocks])
    unpadded_data = unpad(decrypted_data)
    return unpadded_data


def main():
    # Display a welcome message
    print("✨ Welcome to the TEA Encryption and Decryption Program! ✨")
    print("This program is brought to you by Eng. Hala.")
   

    # Ask user to enter the image path
    image_path = input("Please enter the path to the image file: ")

    # Remove any quotation marks and whitespace from the path
    image_path = image_path.strip().strip('"')

    # Print the image path to confirm it's correct
    print(f"You have entered: {image_path}")

    # Ask user to enter the key
    key = input("Please enter the 128-bit key : ")
    key = tuple(int(x, 16) for x in key.split())

    # Ask user to enter the IV
    iv = input("Please enter the 64-bit IV : ")
    iv = tuple(int(x, 16) for x in iv.split())

    # Output directory
    output_dir = "C:\\Users\\halaa\\Desktop\\CryptoProj"

    try:
        # Read the binary data
        with open(image_path, 'rb') as f:
            binary_data = f.read()

        # Separate the BMP header
        header = binary_data[:54]
        image_data = binary_data[54:]

        # Encrypt and decrypt using TEA-ECB mode
        print("Encrypting image using TEA-ECB mode...")
        encrypted_image_data_ecb = TeaEcbEncrypt(image_data, key)
        print("Decrypting image using TEA-ECB mode...")
        decrypted_image_data_ecb = TeaEcbDecrypt(encrypted_image_data_ecb, key)

        # Encrypt and decrypt using TEA-CBC mode
        print("Encrypting image using TEA-CBC mode...")
        encrypted_image_data_cbc = TeaCbcEncrypt(image_data, key, iv)
        print("Decrypting image using TEA-CBC mode...")
        decrypted_image_data_cbc = TeaCbcDecrypt(encrypted_image_data_cbc, key, iv)

        # Define file paths
        encrypted_ecb_path = os.path.join(output_dir, 'encrypted_image_ecb.bmp')
        decrypted_ecb_path = os.path.join(output_dir, 'decrypted_image_ecb.bmp')
        encrypted_cbc_path = os.path.join(output_dir, 'encrypted_image_cbc.bmp')
        decrypted_cbc_path = os.path.join(output_dir, 'decrypted_image_cbc.bmp')

        # Save encrypted and decrypted images
        with open(encrypted_ecb_path, 'wb') as f:
            f.write(header + encrypted_image_data_ecb)
        with open(decrypted_ecb_path, 'wb') as f:
            f.write(header + decrypted_image_data_ecb)
        with open(encrypted_cbc_path, 'wb') as f:
            f.write(header + encrypted_image_data_cbc)
        with open(decrypted_cbc_path, 'wb') as f:
            f.write(header + decrypted_image_data_cbc)

        print(f"Encryption and decryption successful. Files saved as:")
        print(f"  Encrypted ECB: '{encrypted_ecb_path}'")
        print(f"  Decrypted ECB: '{decrypted_ecb_path}'")
        print(f"  Encrypted CBC: '{encrypted_cbc_path}'")
        print(f"  Decrypted CBC: '{decrypted_cbc_path}'")

    except Exception as e:
        print(f"An error occurred: {e}")

if __name__ == "__main__":
    main()

