#!/usr/bin/env python3
"""
CTF Crypto & Stego Toolkit — by S4i1M
==========================================
A quick-use toolkit for CTF crypto and stego challenges.
Run: python3 ctf_toolkit.py
"""

import base64
import binascii
import hashlib
import urllib.parse
import sys

# ─────────────────────────────────────────
#  ENCODING / DECODING
# ─────────────────────────────────────────

def b64_encode(text): return base64.b64encode(text.encode()).decode()
def b64_decode(text): return base64.b64decode(text).decode()

def b32_encode(text): return base64.b32encode(text.encode()).decode()
def b32_decode(text): return base64.b32decode(text).decode()

def b16_encode(text): return text.encode().hex()
def b16_decode(text): return bytes.fromhex(text).decode()

def url_encode(text): return urllib.parse.quote(text)
def url_decode(text): return urllib.parse.unquote(text)

def binary_encode(text):
    return ' '.join(format(ord(c), '08b') for c in text)

def binary_decode(binary):
    bits = binary.replace(' ', '')
    return ''.join(chr(int(bits[i:i+8], 2)) for i in range(0, len(bits), 8))

def hex_to_text(hex_str):
    return bytes.fromhex(hex_str.replace(' ', '').replace('0x', '')).decode()

def text_to_hex(text):
    return text.encode().hex()

# ─────────────────────────────────────────
#  HASHING
# ─────────────────────────────────────────

def md5(text):    return hashlib.md5(text.encode()).hexdigest()
def sha1(text):   return hashlib.sha1(text.encode()).hexdigest()
def sha256(text): return hashlib.sha256(text.encode()).hexdigest()
def sha512(text): return hashlib.sha512(text.encode()).hexdigest()

def identify_hash(h):
    h = h.strip()
    length = len(h)
    is_hex = all(c in '0123456789abcdefABCDEF' for c in h)
    if h.startswith('$2b$') or h.startswith('$2a$'):
        return 'bcrypt'
    if h.startswith('$1$'):  return 'MD5-crypt'
    if h.startswith('$5$'):  return 'SHA-256-crypt'
    if h.startswith('$6$'):  return 'SHA-512-crypt'
    if is_hex:
        sizes = {32:'MD5', 40:'SHA-1', 56:'SHA-224', 64:'SHA-256', 96:'SHA-384', 128:'SHA-512'}
        return sizes.get(length, f'Unknown hex hash (length {length})')
    return 'Unknown hash format'

# ─────────────────────────────────────────
#  CIPHERS
# ─────────────────────────────────────────

def caesar(text, shift, decode=False):
    if decode: shift = -shift
    result = []
    for c in text:
        if c.isalpha():
            base = ord('A') if c.isupper() else ord('a')
            result.append(chr((ord(c) - base + shift) % 26 + base))
        else:
            result.append(c)
    return ''.join(result)

def caesar_brute(text):
    print("\n[CAESAR BRUTE FORCE]")
    for shift in range(1, 26):
        print(f"  ROT{shift:02d}: {caesar(text, shift)}")

def rot13(text): return caesar(text, 13)

def atbash(text):
    result = []
    for c in text:
        if c.isalpha():
            base = ord('A') if c.isupper() else ord('a')
            result.append(chr(base + 25 - (ord(c) - base)))
        else:
            result.append(c)
    return ''.join(result)

def vigenere(text, key, decode=False):
    key = key.upper()
    result = []
    ki = 0
    for c in text:
        if c.isalpha():
            base = ord('A') if c.isupper() else ord('a')
            k = ord(key[ki % len(key)]) - ord('A')
            if decode: k = -k
            result.append(chr((ord(c) - base + k) % 26 + base))
            ki += 1
        else:
            result.append(c)
    return ''.join(result)

# ─────────────────────────────────────────
#  MORSE CODE
# ─────────────────────────────────────────

MORSE = {
    'A':'.-','B':'-...','C':'-.-.','D':'-..','E':'.','F':'..-.','G':'--.','H':'....','I':'..','J':'.---',
    'K':'-.-','L':'.-..','M':'--','N':'-.','O':'---','P':'.--.','Q':'--.-','R':'.-.','S':'...','T':'-',
    'U':'..-','V':'...-','W':'.--','X':'-..-','Y':'-.--','Z':'--..',
    '0':'-----','1':'.----','2':'..---','3':'...--','4':'....-','5':'.....','6':'-....','7':'--...','8':'---..','9':'----.',
    ' ':'/'
}
MORSE_REV = {v:k for k,v in MORSE.items()}

def morse_encode(text):
    return ' '.join(MORSE.get(c.upper(), '?') for c in text)

def morse_decode(code):
    return ''.join(MORSE_REV.get(m, '?') for m in code.split(' ')).lower()

# ─────────────────────────────────────────
#  AUTO IDENTIFIER
# ─────────────────────────────────────────

def identify(text):
    text = text.strip()
    results = []
    is_hex = all(c in '0123456789abcdefABCDEF' for c in text)
    is_b32 = all(c in 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567=' for c in text.upper())

    # Hash detection
    if is_hex:
        if len(text) == 32:  results.append('MD5 Hash (32 hex chars)')
        if len(text) == 40:  results.append('SHA-1 Hash (40 hex chars)')
        if len(text) == 64:  results.append('SHA-256 Hash (64 hex chars)')
        if len(text) == 128: results.append('SHA-512 Hash (128 hex chars)')

    # Base64
    try:
        import re
        if re.match(r'^[A-Za-z0-9+/]+=*$', text) and len(text) % 4 == 0:
            dec = base64.b64decode(text).decode('utf-8', errors='ignore')
            results.append(f'Base64 → decodes to: "{dec[:60]}{"..." if len(dec)>60 else ""}"')
    except: pass

    # Base32
    try:
        if is_b32 and len(text) % 8 == 0:
            dec = base64.b32decode(text.upper()).decode('utf-8', errors='ignore')
            results.append(f'Base32 → decodes to: "{dec[:60]}"')
    except: pass

    # Binary
    bits = text.replace(' ', '')
    if all(c in '01' for c in bits) and len(bits) % 8 == 0:
        dec = binary_decode(bits)
        results.append(f'Binary → decodes to: "{dec[:60]}"')

    # Hex decode
    if is_hex and len(text) % 2 == 0:
        try:
            dec = bytes.fromhex(text).decode('utf-8', errors='ignore')
            results.append(f'Hex → decodes to: "{dec[:60]}"')
        except: pass

    # Morse
    if all(c in '.-/ ' for c in text):
        dec = morse_decode(text)
        results.append(f'Morse Code → decodes to: "{dec}"')

    # URL encoded
    if '%' in text:
        dec = url_decode(text)
        results.append(f'URL Encoded → decodes to: "{dec}"')

    if not results:
        results.append('Could not identify. Try: CyberChef, dcode.fr, or manual analysis.')

    return results

# ─────────────────────────────────────────
#  INTERACTIVE MENU
# ─────────────────────────────────────────

def menu():
    while True:
        print("""
\033[92m
╔══════════════════════════════════════════╗
║   CTF CRYPTO & STEGO TOOLKIT             ║
║   by S4i1M                               ║
╠══════════════════════════════════════════╣
║  1. Auto Identify String                 ║
║  2. Base64 Encode/Decode                 ║
║  3. Base32 Encode/Decode                 ║
║  4. Hex Encode/Decode                    ║
║  5. Binary Encode/Decode                 ║
║  6. URL Encode/Decode                    ║
║  7. Generate Hash (MD5/SHA1/256/512)     ║
║  8. Identify Hash Type                   ║
║  9. Caesar Cipher                        ║
║ 10. Caesar Brute Force (all 25)          ║
║ 11. ROT13                                ║
║ 12. Atbash Cipher                        ║
║ 13. Vigenère Cipher                      ║
║ 14. Morse Code Encode/Decode             ║
║  0. Exit                                 ║
╚══════════════════════════════════════════╝\033[0m""")

        choice = input("\033[92m> \033[0m").strip()

        if choice == '0': sys.exit()

        elif choice == '1':
            text = input("Paste string: ")
            results = identify(text)
            print("\n\033[93m[RESULTS]\033[0m")
            for r in results: print(f"  → {r}")

        elif choice == '2':
            text = input("Text/Base64: ")
            mode = input("Encode or Decode? (e/d): ")
            try:
                print("\033[92mResult:\033[0m", b64_encode(text) if mode=='e' else b64_decode(text))
            except Exception as ex: print("Error:", ex)

        elif choice == '3':
            text = input("Text/Base32: ")
            mode = input("Encode or Decode? (e/d): ")
            try:
                print("\033[93mResult:\033[0m", b32_encode(text) if mode=='e' else b32_decode(text))
            except Exception as ex: print("Error:", ex)

        elif choice == '4':
            text = input("Text or Hex string: ")
            mode = input("Text→Hex or Hex→Text? (e/d): ")
            try:
                print("\033[94mResult:\033[0m", b16_encode(text) if mode=='e' else b16_decode(text))
            except Exception as ex: print("Error:", ex)

        elif choice == '5':
            text = input("Text or Binary: ")
            mode = input("Text→Binary or Binary→Text? (e/d): ")
            try:
                print("\033[94mResult:\033[0m", binary_encode(text) if mode=='e' else binary_decode(text))
            except Exception as ex: print("Error:", ex)

        elif choice == '6':
            text = input("Text or URL-encoded string: ")
            mode = input("Encode or Decode? (e/d): ")
            print("\033[92mResult:\033[0m", url_encode(text) if mode=='e' else url_decode(text))

        elif choice == '7':
            text = input("Text to hash: ")
            print(f"\033[91mMD5:\033[0m    {md5(text)}")
            print(f"\033[91mSHA1:\033[0m   {sha1(text)}")
            print(f"\033[93mSHA256:\033[0m {sha256(text)}")
            print(f"\033[94mSHA512:\033[0m {sha512(text)}")

        elif choice == '8':
            h = input("Paste hash: ")
            print("\033[93mHash type:\033[0m", identify_hash(h))

        elif choice == '9':
            text = input("Text: ")
            shift = int(input("Shift (1-25): "))
            mode = input("Encode or Decode? (e/d): ")
            print("\033[92mResult:\033[0m", caesar(text, shift, decode=(mode=='d')))

        elif choice == '10':
            text = input("Ciphertext: ")
            caesar_brute(text)

        elif choice == '11':
            text = input("Text: ")
            print("\033[92mROT13:\033[0m", rot13(text))

        elif choice == '12':
            text = input("Text: ")
            print("\033[94mAtbash:\033[0m", atbash(text))

        elif choice == '13':
            text = input("Text: ")
            key = input("Key: ")
            mode = input("Encode or Decode? (e/d): ")
            print("\033[95mResult:\033[0m", vigenere(text, key, decode=(mode=='d')))

        elif choice == '14':
            text = input("Text or Morse (use spaces between letters, / for word): ")
            mode = input("Text→Morse or Morse→Text? (e/d): ")
            print("\033[91mResult:\033[0m", morse_encode(text) if mode=='e' else morse_decode(text))

        else:
            print("Invalid choice.")

        input("\n\033[90mPress Enter to continue...\033[0m")

if __name__ == '__main__':
    menu()
