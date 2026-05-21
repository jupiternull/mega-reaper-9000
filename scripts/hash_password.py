#!/usr/bin/env python3
"""Generate a bcrypt hash for use as REAPER_PASSWORD_HASH in .env"""
import sys, bcrypt, secrets

if len(sys.argv) < 2:
    print("Usage: python3 scripts/hash_password.py <password>")
    print("       python3 scripts/hash_password.py --generate  (random password)")
    sys.exit(1)

if sys.argv[1] == '--generate':
    password = secrets.token_urlsafe(16)
    print(f"Generated password: {password}")
else:
    password = sys.argv[1]

hashed = bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode()
print(f"\nAdd to .env:")
print(f"REAPER_PASSWORD_HASH={hashed}")
