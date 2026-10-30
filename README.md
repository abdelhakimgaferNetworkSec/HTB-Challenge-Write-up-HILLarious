# HTB Challenge Write-up: HILLarious

**Platform:** Hack The Box Labs | **Category:** Reversing / Malware Analysis | **Difficulty:** Medium | **XP:** 390

**Author:** Abdel Hakim Gafer

## 1. Scenario

A Blackink-corp server was hit by an executable that encrypted all files of a secret project. The security team recovered the ransomware binary and the encrypted files. The mission: understand the encryption and recover the data.

## 2. Provided Files

The challenge zip (password: `hackthebox`) contains:

| File | Description |
| --- | --- |
| `ransom` | The ransomware executable (8,996 bytes) |
| `secret.txt.enc` | Encrypted file (68 bytes) |
| `document.txt.enc` | Encrypted file (294 bytes) |
| `notes.txt.enc` | Encrypted file (42 bytes) |

## 3. Initial Triage

```bash
file ransom
# ELF 64-bit LSB pie executable, x86-64, statically linked, no section header

strings -n 6 ransom | head -50
```

Key observations:

- `no section header` and a very small size for a static binary suggest packing.
- `strings` revealed the UPX banner: `This file is packed with the UPX executable packer`.

### Unpacking

```bash
upx -d ransom -o ransom_unpacked
# 19835 <- 8996  linux/amd64  ransom_unpacked
```

The unpacked binary is a dynamically linked, stripped ELF. Its imports include `fopen`, `fread`, `fwrite`, `fseek`, `ftell`, `malloc`, `calloc`, `memcpy`, `strcmp`, `remove`, and `time`-related behavior, but no external crypto library (no OpenSSL or libsodium), so the cipher is custom. The usage string is `Usage: %s encrypt <file>`, and the output name is `%s.enc`.

## 4. Analysing the Encrypted Files

```bash
xxd secret.txt.enc | head
```

All `.enc` files start with the magic `SNAR` followed by what looks like a timestamp (the values differ only in the lowest bytes between files), then a length field. This pointed to a custom header worth confirming in the code.

## 5. Static Analysis in Ghidra

The unpacked binary was imported into Ghidra (File > Import File, x86:LE:64), auto-analysed, and explored starting from `entry`.

### 5.1 `main` (FUN\_001011d0)

```c
if (argc == 3 && strcmp(argv[1], "encrypt") == 0)
    return FUN_001018f0(argv[2]);
fprintf(stderr, "Usage: %s encrypt <file>\n", argv[0]);
return 1;
```

### 5.2 Encryption routine (FUN\_001018f0)

The function reads the target file, builds a 20-byte header, encrypts the data, writes `<file>.enc`, verifies the output size, and deletes the original.

```c
local_58 = 0x52414e53;           // "SNAR"
local_54 = time(0);              // 8-byte timestamp
local_4c = (uint32)file_size;    // original size
local_48 = 1;                    // version
FUN_00101680(&header, data, size, &out, &out_len);
fwrite(&header, 1, 0x14, f);
fwrite(out, 1, out_len, f);
```

Resulting file layout:

| Offset | Size | Content |
| --- | --- | --- |
| 0 | 4 | Magic `SNAR` |
| 4 | 8 | Timestamp (u64, little-endian) |
| 12 | 4 | Original file size |
| 16 | 4 | Version (1) |
| 20 | n | Ciphertext |

### 5.3 Key derivation (FUN\_00101680 and FUN\_001015d0)

The 8 timestamp bytes stored in the header are hashed with **FNV-1a (64-bit)** and XORed with a constant:

```c
h = 0xcbf29ce484222325;
for each byte b of header[4:12]:
    h = (h ^ b) * 0x100000001b3;
seed = h ^ 0xdeadbeefcafebabe;
```

`FUN_001015d0` then expands the seed into:

1. An **8-byte XOR key** (the seed in little-endian).
2. A **2x2 matrix** (4 bytes: a, b, c, d) produced by a linear congruential generator, with a fix-up that forces odd values to try to keep the matrix invertible modulo 256.

### 5.4 Cipher (FUN\_001013d0)

The plaintext is padded to an even length (a trailing `0x01` byte), then each byte pair is multiplied by the key matrix modulo 256. This is a **Hill cipher**, which explains the challenge name. The result is XORed with the 8-byte key:

```c
ct[i]   = a * p[i] + b * p[i+1]   (mod 256)
ct[i+1] = c * p[i] + d * p[i+1]   (mod 256)
out[i]  = ct[i] ^ key[i & 7]
```

## 6. The Weakness

The encryption key is derived **entirely from a value stored in plaintext inside the encrypted file** (the timestamp in the header). Anyone holding an `.enc` file can recompute the seed, the XOR key and the Hill matrix, so decryption is possible without paying a ransom and without any secret.

## 7. Decryption

Decryption reverses the steps:

1. Parse the header (magic, timestamp, original size).
2. Recompute `seed = FNV1a64(timestamp) ^ 0xdeadbeefcafebabe`.
3. XOR the ciphertext with the 8-byte key.
4. Multiply each byte pair by the inverse matrix modulo 256, using `inv = det^-1 mod 256` (the determinant must be odd).
5. Truncate to the original size to drop the padding.

### Solver script

```python
#!/usr/bin/env python3
import struct, sys

M64 = (1 << 64) - 1

def fnv1a64(data):
    h = 0xcbf29ce484222325
    for x in data:
        h = ((h ^ x) * 0x100000001b3) & M64
    return h

def gen_matrix(seed):
    lv = (seed * 0x5851f42d4c957f2d + 0x6c576fac43fd007c) & M64
    M, C = 0x4c957f2d, 0xf767814f
    u4 = lv & 0xffffffff
    u1 = (u4 * M + C) & 0xffffffff
    u3 = u1 & 0xff
    a = (u4 & 0xff) | 1
    u1 = (u1 * M + C) & 0xffffffff
    c = u1 & 0xff
    d = (((u1 * M + C) & 0xffffffff) & 0xff) | 1
    b = u3
    if ((a * d - b * c) & 1) == 0:
        a = (((lv & 0xff) | 1) + 2) & 0xff
    return a, b, c, d

def printable(x):
    return 32 <= x < 127 or x in (9, 10, 13)

def decrypt(path):
    data = open(path, 'rb').read()
    assert data[:4] == b'SNAR', "bad magic"
    ts = data[4:12]
    size = struct.unpack('<I', data[12:16])[0]
    ct = data[20:]

    seed = fnv1a64(ts) ^ 0xdeadbeefcafebabe
    ks = struct.pack('<Q', seed)
    a, b, c, d = gen_matrix(seed)

    h = bytes(x ^ ks[i & 7] for i, x in enumerate(ct))
    det = (a * d - b * c) & 0xff
    out = bytearray()

    if det & 1:
        inv = pow(det, -1, 256)
        for i in range(0, len(h), 2):
            o0, o1 = h[i], h[i + 1]
            out.append((inv * (d * o0 - b * o1)) & 0xff)
            out.append((inv * (-c * o0 + a * o1)) & 0xff)
    else:
        # fallback: lookup table, prefer printable candidates
        table = {}
        for x in range(256):
            for y in range(256):
                table.setdefault(((a*x + b*y) & 0xff, (c*x + d*y) & 0xff), []).append((x, y))
        for i in range(0, len(h), 2):
            cands = table.get((h[i], h[i + 1]), [(63, 63)])
            best = next((p for p in cands if printable(p[0]) and printable(p[1])), cands[0])
            out += bytes(best)

    return bytes(out[:size])

for f in sys.argv[1:]:
    print(f"=== {f} ===")
    print(decrypt(f).decode(errors='replace'))
```

```bash
python3 decrypt.py secret.txt.enc notes.txt.enc document.txt.enc
```

## 8. Result

The script recovered all three files. `secret.txt.enc` contained the flag:

```
HTB{h1ll_crypt0syst3m_1s_v3ry_int3rr3st1ng!!!}
```

`notes.txt.enc` held a short note, and `document.txt.enc` held Blackink-corp meeting notes dated 2026-04-01.

## 9. Tools Used

- Kali Linux (VMware)
- `file`, `strings`, `xxd`
- UPX 4.2.4
- Ghidra 12.1.4
- Python 3

## 10. Key Takeaways

- **Always check for packers first.** An unusually small static binary with no section headers is a strong UPX indicator.
- **Map the file format before the algorithm.** The header layout showed which fields the key could depend on.
- **Key material derived from data stored with the ciphertext is no secret.** This is a classic ransomware design flaw that enables recovery without paying.
- **Do not trust decompiler output blindly.** Operator precedence and types (for example `time()` returning 8 bytes) can mislead the header layout, so verify against the actual hex dump.
- **DFIR relevance:** when facing a ransomware sample, unpack it, locate the key derivation, then reimplement the decryptor. Always analyse inside an isolated VM.
