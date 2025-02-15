#!/usr/bin/env python3
"""
Must_Hash Identifier
Version: 1.0
Author: AM_Turing
Inspired by the original by Zion3R (www.Blackploit.com)

Note: Many hash types share the same length and character set so identification is often ambiguous.
"""

import re
import sys
import os

# Expanded list of hash patterns.
HASH_PATTERNS = [
    # 128-bit hashes (32 hex digits)
    {"name": "MD2", "regex": r"^[a-f0-9]{32}$"},
    {"name": "MD4", "regex": r"^[a-f0-9]{32}$"},
    {"name": "MD5", "regex": r"^[a-f0-9]{32}$"},
    {"name": "NTLM", "regex": r"^[A-F0-9]{32}$"},
    {"name": "LM", "regex": r"^[A-F0-9]{32}$"},
    {"name": "RIPEMD-128", "regex": r"^[a-f0-9]{32}$"},
    {"name": "Snefru-128", "regex": r"^[a-f0-9]{32}$"},
    
    # 16-bit CRC / FCS16 (4 hex digits)
    {"name": "CRC16 / FCS16", "regex": r"^[a-f0-9]{4}$"},
    
    # 32-bit hashes (8 hex digits)
    {"name": "CRC32 / ADLER32", "regex": r"^[a-f0-9]{8}$"},
    {"name": "XOR32", "regex": r"^[a-f0-9]{8}$"},
    
    # 160-bit hashes (40 hex digits)
    {"name": "SHA-1", "regex": r"^[a-f0-9]{40}$"},
    {"name": "RIPEMD-160", "regex": r"^[a-f0-9]{40}$"},
    
    # 224-bit hashes (56 hex digits)
    {"name": "SHA-224", "regex": r"^[a-f0-9]{56}$"},
    {"name": "SHA3-224", "regex": r"^[a-f0-9]{56}$"},
    {"name": "HAVAL-224", "regex": r"^[a-f0-9]{56}$"},
    
    # 256-bit hashes (64 hex digits)
    {"name": "SHA-256", "regex": r"^[a-f0-9]{64}$"},
    {"name": "SHA3-256", "regex": r"^[a-f0-9]{64}$"},
    {"name": "RIPEMD-256", "regex": r"^[a-f0-9]{64}$"},
    {"name": "HAVAL-256", "regex": r"^[a-f0-9]{64}$"},
    {"name": "Snefru-256", "regex": r"^[a-f0-9]{64}$"},
    {"name": "BLAKE2s", "regex": r"^[a-f0-9]{64}$"},
    
    # 320-bit hash (80 hex digits)
    {"name": "RIPEMD-320", "regex": r"^[a-f0-9]{80}$"},
    
    # 384-bit hashes (96 hex digits)
    {"name": "SHA-384", "regex": r"^[a-f0-9]{96}$"},
    {"name": "SHA3-384", "regex": r"^[a-f0-9]{96}$"},
    
    # 512-bit hashes (128 hex digits)
    {"name": "SHA-512", "regex": r"^[a-f0-9]{128}$"},
    {"name": "SHA3-512", "regex": r"^[a-f0-9]{128}$"},
    {"name": "Whirlpool", "regex": r"^[a-f0-9]{128}$"},
    {"name": "BLAKE2b", "regex": r"^[a-f0-9]{128}$"},
    
    # Unix crypt variants
    {"name": "DES Crypt", "regex": r"^\$1\$[./A-Za-z0-9]{1,}\$[./A-Za-z0-9]+$"},
    {"name": "bcrypt", "regex": r"^\$2[aby]\$[0-9]{2}\$[./A-Za-z0-9]{53}$"},
    {"name": "SHA-256 Crypt", "regex": r"^\$5\$.*"},
    {"name": "SHA-512 Crypt", "regex": r"^\$6\$.*"},
    
    # Joomla / PHPass formats
    {"name": "Joomla", "regex": r"^[a-f0-9]{32}:[a-zA-Z0-9\/\.]+$"},
    {"name": "PHPass", "regex": r"^\$P\$[./A-Za-z0-9]{31}$"},
    
    # Django formats
    {"name": "Django SHA-1", "regex": r"^sha1\$[a-zA-Z0-9]+\$[a-f0-9]{40}$"},
    {"name": "Django SHA-256", "regex": r"^sha256\$[a-zA-Z0-9]+\$[a-f0-9]{64}$"},
    {"name": "Django SHA-384", "regex": r"^sha384\$[a-zA-Z0-9]+\$[a-f0-9]{96}$"},
    {"name": "Django SHA-512", "regex": r"^sha512\$[a-zA-Z0-9]+\$[a-f0-9]{128}$"},
    
    # LDAP / SSHA / SMD5 formats (Base64-encoded)
    {"name": "LDAP SHA", "regex": r"^\{SHA\}[A-Za-z0-9+/]+=?$"},
    {"name": "SSHA", "regex": r"^\{SSHA\}[A-Za-z0-9+/]+=?$"},
    {"name": "SMD5", "regex": r"^\{SMD5\}[A-Za-z0-9+/]+=?$"},
    
    # Modern password hashing algorithms
    {"name": "Argon2", "regex": r"^\$argon2(?:i|d|v)\$.*"},
    {"name": "scrypt", "regex": r"^\$7\$[0-9A-Za-z\/\.]+\$[0-9A-Za-z\/\.]+$"},
    
    # Windows SAM format (LM:NTLM combined)
    {"name": "Windows LM:NTLM", "regex": r"^[a-f0-9]{32}:[a-f0-9]{32}$"},
]

LOGO = r'''
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢀⣀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢀⣴⣾⡿⠿⢿⣿⣶⣄⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣀⣀⣀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⢠⡿⠋⠀⠀⠀⠀⠈⠙⠿⣿⣄⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣠⣴⣾⣿⣿⡿⠿⣿⣶⡄⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠛⠀⠀⠀⠀⠀⠀⠀⠀⠀⠈⠻⣷⡀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢀⣴⣿⣿⣿⠟⠋⠀⠀⠀⠀⠙⢿⣦⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣠⣤⣤⡀⠀⠀⠈⠉⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢀⣴⣿⣿⡿⠋⠀⠀⠀⠀⠀⠀⠀⠀⠀⠻⠆⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣸⣿⣿⣿⣿⣆⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣰⣿⣿⠟⠁⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣿⣿⣿⣿⣿⣿⡄⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢀⣾⣿⠟⠁⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣿⣿⣿⣿⣿⣿⣷⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢠⣾⠟⠁⠀⠀⠀⠀⠀⠀⠀⣀⣀⣀⣤⣤⣤⣤⡀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣿⣿⣿⣿⣿⣿⣿⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢰⠟⠁⠀⠀⠀⠀⢀⣠⣴⣾⣿⣿⣿⣿⣿⣿⣿⣟⠋⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣿⣿⣿⣿⣿⣿⣿⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣠⣾⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⡷⠆⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠸⣿⣿⣿⣿⣿⣿⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠘⠻⠿⠿⠿⠛⠋⠁⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠹⣿⣿⣿⣿⡏⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠈⠻⠿⠋⠀⠀⠀⣀⣀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣀⣀⡀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⣀⣤⣶⣶⣤⣄⡀⠀⠀⠀⠀⠀⠀⠀⠀⢀⣠⣴⣶⣿⣿⣿⣿⣿⣿⣷⣦⣄⡀⣀⣤⣶⣿⣿⣿⣿⣿⣿⣿⣷⣶⣤⣀⠀⠀⠀⠀⠀⠀⠀⠀⣠⣶⢾⣿⣷⣦⡀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⢀⣼⣿⣿⠏⠁⠀⠈⠁⠀⠀⠀⠀⠀⣀⣴⣾⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣷⣦⣀⠀⠀⠀⠀⠀⠉⠁⠀⠈⢻⣿⣿⣦⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⣸⣿⣿⣿⠀⠀⠀⠀⠀⠀⢀⣤⣶⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣷⣦⣄⠀⠀⠀⠀⠀⠀⢀⣿⣿⣿⡇⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⢿⣿⣿⣿⣦⣀⣀⣤⣴⣾⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣶⣤⣄⣠⣤⣾⣿⣿⣿⡇⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠸⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⡿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⠃⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠹⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⡿⠟⠉⠀⠀⠙⠿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⡿⠃⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠈⠛⢿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⡿⠿⠛⠋⠁⠀⠀⠀⠀⠀⠀⠀⠀⠉⠛⠻⠿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⡿⠟⠋⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠉⠙⠛⠻⠿⠿⠿⠿⠿⠟⠛⠛⠋⠉⠉⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠈⠉⠉⠛⠛⠛⠛⠛⠿⠿⠿⠛⠛⠋⠉⠁⠀⠀⠀⠀

   MUST_HASH IDENTIFIER v1.0 - Updated by AM_Turing
Inspired by the original by Zion3R (www.Blackploit.com)
'''

def identify_hash(hash_str):
    """
    Given a hash string, return a list of matching algorithm names.
    """
    matches = []
    for entry in HASH_PATTERNS:
        if re.fullmatch(entry["regex"], hash_str, flags=re.IGNORECASE):
            matches.append(entry["name"])
    return matches

def main():
    print(LOGO)
    
    # Use first command-line argument if provided, otherwise prompt repeatedly.
    input_hash = sys.argv[1] if len(sys.argv) > 1 else None

    try:
        while True:
            if input_hash is None:
                hash_str = input("HASH: ").strip()
            else:
                hash_str = input_hash.strip()
            
            if not hash_str:
                print("Please enter a non-empty hash.")
                input_hash = None
                continue

            results = identify_hash(hash_str)

            if not results:
                print("\n[!] No matching algorithm could be identified.\n")
            else:
                # Remove duplicates and sort the results
                results = sorted(set(results))
                if len(results) == 1:
                    print("\n[+] Identified hash type: " + results[0] + "\n")
                else:
                    print("\n[+] Possible hash types:")
                    for algo in results:
                        print("    - " + algo)
                    print()

            # Reset command-line argument after first use
            input_hash = None

    except KeyboardInterrupt:
        print("\n\nBye!")
        sys.exit(0)

if __name__ == "__main__":
    main()
