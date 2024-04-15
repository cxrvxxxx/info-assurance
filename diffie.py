from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend

import sys
import string
import random

def encrypt_chunk(chunk, key):
    key = key.encode('utf-8')

    # Create an AES cipher object with the provided key
    cipher = Cipher(algorithms.AES(key), modes.ECB(), backend=default_backend())
    encryptor = cipher.encryptor()

    # Encrypt the chunk
    encrypted_chunk = encryptor.update(chunk) + encryptor.finalize()

    return encrypted_chunk

def chunkify(message, chunk_size=16, encoding='utf-8'):
    message_bytes = message.encode(encoding)

    chunks = []
    for i in range(0, len(message_bytes), chunk_size):
        chunk = message_bytes[i: i + chunk_size]

        while len(chunk) < chunk_size:
            chunk += '@'.encode(encoding)

        chunks.append(chunk)

    return chunks

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

    p_key_a = generate_key()
    print(f"User A PRIVATE_KEY: {p_key_a}")

    pub_a = (g**ord(p_key_a)) % p
    print(f"User A PUBLIC_VALUE: {pub_a}")

    p_key_b = generate_key()
    print(f"User B PRIVATE_KEY: {p_key_b}")

    pub_b = (g**ord(p_key_b)) % p
    print(f"User B PUBLIC_VALUE: {pub_b}")

    s_key_a = (pub_b**ord(p_key_a)) % p
    print(f"Shared key (A compute): {to_aes(s_key_a)}")

    s_key_b = (pub_a**ord(p_key_b)) % p
    print(f"Shared key (B compute): {to_aes(s_key_b)}")

    chunks = chunkify(message)

    print("Message chunks: ")
    print_chunks(chunks)

    encrypted = []
    for chunk in chunks:
        encrypted.append(encrypt_chunk(chunk, to_aes(s_key_a)))

    print("Encrypted chunks:")
    print_chunks(encrypted)

if __name__ == '__main__':
    main()
