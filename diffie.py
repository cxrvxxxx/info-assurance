from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend

import sys
import string
import random

def encrypt_chunk(chunk, key):
    key = key.encode('utf-8')

    cipher = Cipher(algorithms.AES(key), modes.ECB(), backend=default_backend())
    encryptor = cipher.encryptor()

    encrypted_chunk = encryptor.update(chunk) + encryptor.finalize()

    return encrypted_chunk

def decrypt_chunk(encrypted_chunk, key):
    key = key.encode('utf-8')

    cipher = Cipher(algorithms.AES(key), modes.ECB(), backend=default_backend())
    decryptor = cipher.decryptor()

    decrypted_chunk = decryptor.update(encrypted_chunk) + decryptor.finalize()

    return decrypted_chunk

def chunkify(message, chunk_size=16, encoding='utf-8'):
    message_bytes = message.encode(encoding)

    chunks = []
    for i in range(0, len(message_bytes), chunk_size):
        chunk = message_bytes[i: i + chunk_size]

        while len(chunk) < chunk_size:
            chunk += '@'.encode(encoding)

        chunks.append(chunk)

    return chunks

def dechunkify(chunks, encoding='utf-8'):
    concatenated_bytes = b''.join(chunks)
    message = concatenated_bytes.replace('@'.encode(encoding), b'')  # Remove padding bytes
    message = message.rstrip(b'\x00')
    return message.decode(encoding)

def print_chunks(chunks):
    for i, chunk in enumerate(chunks):
        print(f"Chunk {i+1}: {chunk} ({len(chunk) * 8} bits)")

def generate_key():
    return random.choice(string.printable[:-5])

def to_aes(value):
    string_val = str(value)

    if len(string_val) == 1:
        return ''.join([f'{string_val}C' for _ in range(8)])
    elif len(string_val) == 2:
        return ''.join([f'{string_val}DD' for _ in range(4)])
    elif len(string_val) == 3:
        return ''.join([f'{string_val}F' for _ in range(4)])

def main():
    if len(sys.argv) != 2:
        print("Usage: py diffie.py <message>")
        sys.exit(1)
    
    message = sys.argv[1]
    p = 199
    g = 127

    print()

    p_key_a = generate_key()
    print(f"User A PRIVATE_KEY: {p_key_a}")

    pub_a = (g**ord(p_key_a)) % p
    print(f"User A PUBLIC_VALUE: {pub_a}")

    p_key_b = generate_key()
    print(f"User B PRIVATE_KEY: {p_key_b}")

    pub_b = (g**ord(p_key_b)) % p
    print(f"User B PUBLIC_VALUE: {pub_b}")

    print()

    s_key_a = (pub_b**ord(p_key_a)) % p
    print(f"Shared key (A compute): {to_aes(s_key_a)}")

    s_key_b = (pub_a**ord(p_key_b)) % p
    print(f"Shared key (B compute): {to_aes(s_key_b)}")

    chunks = chunkify(message)

    print()

    print("Message chunks: ")
    print_chunks(chunks)

    encrypted = []
    for chunk in chunks:
        encrypted.append(encrypt_chunk(chunk, to_aes(s_key_a)))

    print()

    print("Encrypted chunks:")
    print_chunks(encrypted)

    print()

    decrypted = []
    for encrypted_chunk in encrypted:
        decrypted.append(decrypt_chunk(encrypted_chunk, to_aes(s_key_a)))
    
    print("Decrypted chunks:")
    print_chunks(decrypted)

    dechunkified = dechunkify(decrypted)

    print()

    print(f"Decoded message: {dechunkified}")

if __name__ == '__main__':
    main()
