# 🔐 CTF Crypto & Steganography Cheatsheet

> A quick reference for CTF crypto and stego challenges.  
> By **S4i1M** — B.Tech 

---

## 📋 Table of Contents
- [Auto-Identification Guide](#-auto-identification-guide)
- [Base Encodings](#-base-encodings)
- [Hash Reference](#-hash-reference)
- [Classical Ciphers](#-classical-ciphers)
- [Steganography](#-steganography)
- [Online Tools](#-online-tools)
- [Python Quick Scripts](#-python-quick-scripts)

---

## 🔍 Auto-Identification Guide

Look at the string and match the pattern:

| Pattern | Likely Encoding |
|---------|----------------|
| Only `A-Z`, `2-7`, ends with `=` | Base32 |
| `A-Za-z0-9+/`, ends with `=` or `==` | Base64 |
| Only `0-9`, `a-f`, even length | Hex / Base16 |
| Only `0` and `1`, groups of 8 | Binary |
| Only `.`, `-`, `/` and spaces | Morse Code |
| `%xx` format | URL Encoded |
| 32 hex chars | MD5 Hash |
| 40 hex chars | SHA-1 Hash |
| 64 hex chars | SHA-256 Hash |
| 128 hex chars | SHA-512 Hash |
| Starts with `$2b$` | bcrypt Hash |
| `CTF{...}` or `flag{...}` | You found it! 🎉 |

> **Tip:** If one decode gives gibberish, try decoding again — flags are often multi-layered (e.g., Base64 of a Caesar of Hex).

---

## 📦 Base Encodings

### Base64
```
Charset: A-Z a-z 0-9 + / =
Padding: ends with = or ==
Length:  always multiple of 4
```
```bash
# Encode
echo -n "Hello" | base64

# Decode
echo "SGVsbG8=" | base64 -d
```

### Base32
```
Charset: A-Z and 2-7 (uppercase only)
Padding: always ends with =
Length:  always multiple of 8
```
```python
import base64
base64.b32encode(b"Hello")   # encode
base64.b32decode("JBSWY3DP") # decode
```

### Hex (Base16)
```
Charset: 0-9 a-f only
Length:  always even
Often prefixed with: 0x
```
```bash
# Text to hex
echo -n "Hello" | xxd -p

# Hex to text
echo "48656c6c6f" | xxd -r -p
```

### Binary
```
Charset: 0 and 1 only
Groups:  8 bits per character
Space:   usually separates each byte
```
```python
# Text to binary
' '.join(format(ord(c), '08b') for c in "Hi")

# Binary to text
''.join(chr(int(b, 2)) for b in "01001000 01101001".split())
```

---

## 🔒 Hash Reference

| Hash | Length | Example |
|------|--------|---------|
| MD5 | 32 hex chars | `5d41402abc4b2a76b9719d911017c592` |
| SHA-1 | 40 hex chars | `aaf4c61ddcc5e8a2dabede0f3b482cd9aea9434d` |
| SHA-256 | 64 hex chars | `185f8db32921bd46d35...` |
| SHA-512 | 128 hex chars | `9b71d224bd62f37...` |
| bcrypt | 60 chars | `$2b$12$...` |

### Hash Cracking (for CTFs)
```
1. crackstation.net    — huge wordlist, best first try
2. hashes.com          — online lookup
3. hashcat / john      — local offline cracking

# John the Ripper
john --wordlist=/usr/share/wordlists/rockyou.txt hash.txt

# Hashcat
hashcat -m 0 hash.txt rockyou.txt       # MD5
hashcat -m 100 hash.txt rockyou.txt     # SHA-1
hashcat -m 1400 hash.txt rockyou.txt    # SHA-256
```

---

## 🔤 Classical Ciphers

### Caesar Cipher
Shifts letters by N positions. ROT13 = shift of 13.

```bash
# ROT13 (Linux)
echo "Uryyb" | tr 'A-Za-z' 'N-ZA-Mn-za-m'

# Brute force all 25 shifts (Python)
for i in range(1,26):
    print(f"ROT{i}:", ''.join(chr((ord(c)-65+i)%26+65) if c.isupper()
          else chr((ord(c)-97+i)%26+97) if c.islower()
          else c for c in ciphertext))
```

### ROT13
Special case of Caesar (shift=13). Its own inverse — applying twice restores original.
```python
import codecs
codecs.encode("Hello", 'rot_13')  # → Uryyb
```

### Atbash
A=Z, B=Y, C=X... mirror substitution. Symmetric — same operation decodes and encodes.
```python
''.join(chr(ord('Z')-(ord(c)-ord('A'))) if c.isupper()
        else chr(ord('z')-(ord(c)-ord('a'))) if c.islower()
        else c for c in text)
```

### Vigenère Cipher
Repeating keyword shifts each letter. Harder to spot — frequency analysis looks flat.
```
Key: SECRET
Plaintext:  HELLO
Ciphertext: ZINCS  (H+S, E+E, L+C, L+R, O+E mod 26)
```
Use **dcode.fr/vigenere-cipher** if you don't have the key — it can guess it.

### Morse Code
```
Only characters: . - / (space)
Letter separator: space
Word separator:   /

SOS = ... --- ...
```

---

## 🖼️ Steganography

### Checklist — Start Here (Every File)
```bash
file suspicious_file          # confirm real file type
strings suspicious_file       # look for hidden text
exiftool image.png            # metadata analysis
binwalk -e file.png           # extract embedded files
xxd file.png | head -20       # view hex header / magic bytes
```

### Image Files (PNG / JPG)
```bash
# Try steghide with empty password first
steghide extract -sf image.jpg
steghide extract -sf image.jpg -p ""

# LSB analysis (PNG)
zsteg -a image.png

# Visual analysis
stegsolve         # open in Stegsolve.jar → flip through bit planes

# Check for appended data after EOF
xxd image.jpg | tail -20     # JPG ends at FF D9
```

### Audio Files (WAV / MP3)
```
1. Open in Audacity
2. Change track view to Spectrogram
3. Look for text/patterns in the frequency spectrum
4. Flags are often written visually in the spectrogram!

# MP3 stego
mp3stego-decode -X -P password file.mp3 output.txt
```

### File Magic Bytes (Signatures)
If `file` says it's not what the extension claims, rename using the real type:

| File Type | Magic Bytes (Hex) | ASCII |
|-----------|------------------|-------|
| PNG | `89 50 4E 47 0D 0A 1A 0A` | `‰PNG` |
| JPG | `FF D8 FF` | |
| GIF | `47 49 46 38` | `GIF8` |
| ZIP | `50 4B 03 04` | `PK..` |
| PDF | `25 50 44 46` | `%PDF` |
| ELF | `7F 45 4C 46` | `.ELF` |
| MP3 | `49 44 33` | `ID3` |

### LSB (Least Significant Bit) Steganography
Data hidden in the last bit of each pixel's R/G/B value. Not visible to the eye.
```bash
zsteg -a image.png          # tries all LSB combinations automatically
python3 lsb_extract.py      # manual: read bit 0 of each pixel
```

### Common Stego Passwords to Try
```
""  (empty)   |  password  |  secret  |  ctf  |  flag  |  admin  |  1234
```

---

## 🌐 Online Tools

| Tool | Use For |
|------|---------|
| **cyberchef.org** | All-in-one, try this first for everything |
| **dcode.fr** | Cipher identification + solving |
| **crackstation.net** | Hash cracking (huge wordlist) |
| **hashes.com** | Hash lookup and cracking |
| **cryptii.com** | Visual encoding chains |
| **stegonline.rodrigo.be** | Online image stego analysis |
| **stylesuxx.github.io/steganography** | Online LSB encode/decode |
| **morsecode.world** | Morse encode/decode + audio |
| **asciitohex.com** | ASCII / Hex / Binary converter |

---

## 🐍 Python Quick Scripts

### Decode anything automatically
```python
import base64, binascii, urllib.parse

def try_all(text):
    print("Base64:", base64.b64decode(text).decode(errors='ignore'))
    print("Base32:", base64.b32decode(text).decode(errors='ignore'))
    print("Hex:   ", bytes.fromhex(text).decode(errors='ignore'))
    print("URL:   ", urllib.parse.unquote(text))
```

### Caesar brute force
```python
def brute_caesar(text):
    for shift in range(1, 26):
        result = ''.join(
            chr((ord(c) - (65 if c.isupper() else 97) + shift) % 26 + (65 if c.isupper() else 97))
            if c.isalpha() else c for c in text
        )
        print(f"ROT{shift:02d}: {result}")
```

### XOR decode (common in CTFs)
```python
def xor_decode(data: bytes, key: int) -> str:
    return ''.join(chr(b ^ key) for b in data)

# Brute force XOR single byte key
def xor_brute(data: bytes):
    for key in range(256):
        result = xor_decode(data, key)
        if 'CTF{' in result or 'flag{' in result:
            print(f"Key {key}: {result}")
```

### Extract LSB from image
```python
from PIL import Image

def extract_lsb(image_path):
    img = Image.open(image_path)
    pixels = list(img.getdata())
    bits = ''
    for pixel in pixels:
        for channel in pixel[:3]:  # R, G, B
            bits += str(channel & 1)
    chars = [bits[i:i+8] for i in range(0, len(bits), 8)]
    return ''.join(chr(int(c, 2)) for c in chars if int(c, 2) != 0)
```

---

## 📝 Notes

- Always try **CyberChef** first — use the "Magic" operation to auto-detect
- Flags are often nested — if decode gives gibberish, decode again
- For image stego: **always check metadata AND LSB AND appended data**
- For audio stego: **always check spectrogram in Audacity**
- `strings` + `binwalk` are your best friends in stego

---

*Made with ☕ during CTF season | Sriram SK | B.Tech CSE (Cybersecurity)*
