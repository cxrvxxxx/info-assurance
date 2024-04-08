import sys

def string_to_ascii(char, normalize=False) -> int:
    return ord(char) - ord('a') if normalize else ord(char)

def generate_vignere_table() -> list:
    table = []
    
    for r in range(26):
        row = []
        for c in range(26):
            row.append((r + c) % 26)
        table.append(row)

    return table

def decrypt_vignere(ciphertext, key) -> str:
    normalized_ct = [string_to_ascii(c, normalize=True) for c in ciphertext]
    normalized_key = [string_to_ascii(c, normalize=True) for c in key]
    table = generate_vignere_table()
    key_ctr = 0
    plaintext = ''

    for i in range(len(normalized_ct)):
        c = normalized_ct[i]
        r = normalized_key[key_ctr]

        plaintext += chr(table[r][c] + ord('a'))

    return plaintext

def decrypt_caesar(ciphertext, shift) -> str:
    plaintext = ''
    for c in ciphertext:
        normalized_c = string_to_ascii(c, normalize=True)
        shifted_c = ((normalized_c - shift + 26) % 26)
        plaintext += chr(shifted_c + ord('a'))

    return plaintext

if __name__ == '__main__':
    ciphertext = 'owgysmwcykiwyomgee'

    print(f"Given ciphertext: {ciphertext}")

    print("Stage 2 Decryption (Caesar's Cipher)")
    caesar_decoded_messages = []
    for i in range(26):
        plaintext = decrypt_caesar(ciphertext, i)
        caesar_decoded_messages.append(plaintext)
        print(f"Shift: {i}\t Decoded message: {plaintext}")

    print("Stage 1 Decryption (Vignere)")
    for m in caesar_decoded_messages:
        vignere_key = m
        vignere_decoded = decrypt_vignere(ciphertext, vignere_key)

        print(f"Key: {vignere_key}\t Decoded message: {vignere_decoded}")
