import numpy as np
import string

def load_messages(file_path):
    with open(file_path, 'r') as f:
        return [line.strip().encode() for line in f.readlines()]

def load_ciphertexts(file_path):
    with open(file_path, 'r') as file:
        lines = file.readlines()
    return [bytes.fromhex(encoded_str.strip()) for encoded_str in lines]
def load_cipher_file(file_path):
    with open(file_path, 'r') as f:
        ciphers = f.read().splitlines()
    return ciphers

def split_ciphertexts(byte_cipher_array):
    cipher1_array = [key[:16] for key in byte_cipher_array]
    cipher2_array = [key[16:] for key in byte_cipher_array]
    return cipher1_array, cipher2_array

def generate_keys(cipher1_array, messages):
    keys = [[None for _ in range(len(messages))] for _ in range(len(cipher1_array))]
    for i in range(len(cipher1_array)):
        for j in range(len(messages)):
            keys[i][j] = bytes([m ^ k for m, k in zip(messages[j], cipher1_array[i])])
    return keys

def find_common_keys(keys):
    sets = [set(row) for row in keys]
    common_keys = set.intersection(*sets)
    return list(common_keys)

def decrypt_plaintext(cipher1_array, common_key):
    plain_text = [None] * 12
    for i in range(12):
        result = bytes([m ^ k for m, k in zip(cipher1_array[i], common_key)])
        plain_text[i] = result
    return plain_text

def xor_strings(a, b):
    return ''.join(chr(ord(a[i]) ^ ord(b[i])) for i in range(len(a)))

def int_array_xor(a, b):
    return [x ^ y for x, y in zip(a, b)]

def check_if_upper(x):
    return 'A' <= x <= 'Z'

def check_if_lower(x):
    return 'a' <= x <= 'z'

def chnage_to_character(lis):
    set_of_plain_text = string.ascii_letters + string.digits + ".,?!-:\";' "
    res = ""
    for num in lis:
        ch = chr(num)
        if ch in set_of_plain_text:
            res += ch
        else:
            res += '_'
    return res

def recover_key(plaintext,ciphertext):
    
    plaintext_ascii = [ord(char) for char in plaintext]
    min_length = min(len(plaintext_ascii), len(ciphertext))
    key = [plaintext_ascii[i] ^ ciphertext[i] for i in range(min_length)]

    return key

def save_to_file(filename, data):
    with open(filename, 'a') as file: 
        file.write(data + '\n')
    

def main():
    messages = load_messages('./dictionary.txt')
    byte_cipher_array = load_ciphertexts('cipherText.txt')
    ciphers = load_cipher_file("cipherText.txt")
    cipher1_array,cipher2_array = split_ciphertexts(byte_cipher_array)

    ciphers_int = []

    for cipher in ciphers:
        lis2 = [int(cipher[i:i+2], 16) for i in range(0, len(cipher), 2)]
        ciphers_int.append(lis2)
    ciphers_int = [key[16:] for key in ciphers_int]   
    
    keys = generate_keys(cipher1_array, messages)
    common_keys = find_common_keys(keys)
    save_to_file('plaintext.txt', f"Key for the first  16 bytes: {common_keys[0]}")
    plain_text = decrypt_plaintext(cipher1_array, common_keys[0])
    for i in range(12):
        save_to_file('plaintext.txt', f"Plane text for the first 16 bytes {i+1} is: {plain_text[i].decode()}")

    
    max_cipher_length = max(len(cipher) for cipher in ciphers_int)
    key = [0] * max_cipher_length
    
    for i in range(len(ciphers_int)):
        space_index = [0] * len(ciphers_int[i])
        for j in range(i + 1, len(ciphers_int)):
            xorred = int_array_xor(ciphers_int[i], ciphers_int[j])
            for k in range(len(xorred)):
                if check_if_upper(chr(xorred[k])) or check_if_lower(chr(xorred[k])):
                    if k < len(space_index):
                        space_index[k] += 1
                    else:
                        space_index.append(1)
        for k in range(len(space_index)):
            if space_index[k] > 2 and k < len(ciphers_int[i]):
                key[k] = ciphers_int[i][k] ^ ord(' ')
       
    messages = []
    print("Expected message be like:")
    for i, cipher in enumerate(ciphers_int):
        broken = int_array_xor(cipher, key)
        message = chnage_to_character(broken)
        messages.append(message)
        save_to_file('plaintext.txt', f"Expected plaintext {i+1}: {plain_text[i].decode()}  {message}")


    plaintext="interpretation was initiated by a psychology student, who marveled at how simple symmetrical patterns could evoke such a wide range of experiences."

    key = recover_key(plaintext, ciphers_int[1])
    byte_representation = bytes(key)
    save_to_file('plaintext.txt', f"Key for the last 16 bytes: {byte_representation}")


if __name__ == "__main__":
    main()
