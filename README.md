# Hash Identifier v1.0

**Hash Identifier** is a Python script designed to identify the algorithm used to generate a given hash string. It leverages an extensive set of regular expressions to match many common (and some modern) hash formats. The tool is inspired by the original version by Zion3R (Blackploit), but has been significantly modified.
## Features

- **Extensive Hash Support:**  
  Detects numerous hash formats including but not limited to:
  - **128-bit Hashes:** MD2, MD4, MD5, NTLM, LM, RIPEMD-128, Snefru-128
  - **CRC and XOR Hashes:** CRC16/FCS16, CRC32/ADLER32, XOR32
  - **160-bit Hashes:** SHA-1, RIPEMD-160
  - **224-bit Hashes:** SHA-224, SHA3-224, HAVAL-224
  - **256-bit Hashes:** SHA-256, SHA3-256, RIPEMD-256, HAVAL-256, Snefru-256, BLAKE2s
  - **320-bit Hashes:** RIPEMD-320
  - **384-bit Hashes:** SHA-384, SHA3-384
  - **512-bit Hashes:** SHA-512, SHA3-512, Whirlpool, BLAKE2b
  - **Unix Crypt Variants:** DES Crypt, bcrypt, SHA-256 Crypt, SHA-512 Crypt
  - **Web and Application Formats:** Joomla, PHPass, Django (SHA-1, SHA-256, SHA-384, SHA-512)
  - **LDAP/SSHA/SMD5:** Base64-encoded hash formats often used in LDAP directories
  - **Modern Password Hashing:** Argon2, scrypt
  - **Windows SAM Format:** Combined LM:NTLM hashes

- **Interactive and CLI Modes:**  
  Run the tool interactively to enter hashes one by one or pass a hash as a command-line argument.

## Requirements

- **Python Version:** Python 3.x (tested on Python 3.6+)
- **Dependencies:**  
  Uses only built-in Python modules (`re`, `sys`, `os`). No external dependencies are required.

## Installation

1. **Clone the Repository:**
   ```bash
   git clone https://github.com/AM-Turing/hash-identifier.git
   cd hash-identifier
