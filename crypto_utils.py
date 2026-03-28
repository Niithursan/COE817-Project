"""
crypto_utils.py - Cryptographic Utility Functions for COE817 Secure Banking System
===================================================================================
Provides all cryptographic primitives for the secure banking application:

  - AES-CBC symmetric encryption and decryption (with PKCS7 padding)
  - HMAC-SHA256 message authentication codes (MAC)
  - HKDF-based key derivation (Master Secret -> K_enc + K_mac)
  - Master Secret generation from pre-shared key + nonces
  - Nonce and timestamp generation / verification
  - Length-prefixed field packing/unpacking for binary protocols
  - Socket communication helpers (send/recv with length prefix)
  - Password hashing (SHA-256 based)
"""

import time
import struct
import hmac
import hashlib
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad


# ============================================================
# AES Symmetric Encryption (CBC mode with PKCS7 padding)
# ============================================================

def aes_encrypt(key, plaintext_bytes):
    """
    Encrypt data using AES in CBC mode with PKCS7 padding.

    A random 16-byte IV is generated and prepended to the ciphertext
    so the receiver can extract it for decryption.

    Format of output: [16-byte IV][ciphertext]

    Args:
        key: AES key (16 bytes for AES-128)
        plaintext_bytes: data to encrypt

    Returns:
        IV + ciphertext bytes
    """
    iv = get_random_bytes(AES.block_size)  # 16 bytes
    cipher = AES.new(key, AES.MODE_CBC, iv)
    padded = pad(plaintext_bytes, AES.block_size)
    ciphertext = cipher.encrypt(padded)
    return iv + ciphertext


def aes_decrypt(key, iv_and_ciphertext):
    """
    Decrypt AES-CBC encrypted data.

    Expects the first 16 bytes to be the IV, followed by ciphertext.

    Args:
        key: AES key (same key used for encryption)
        iv_and_ciphertext: IV + ciphertext bytes

    Returns:
        Decrypted plaintext bytes (padding removed)
    """
    iv = iv_and_ciphertext[:AES.block_size]
    ciphertext = iv_and_ciphertext[AES.block_size:]
    cipher = AES.new(key, AES.MODE_CBC, iv)
    padded = cipher.decrypt(ciphertext)
    return unpad(padded, AES.block_size)


# ============================================================
# HMAC-SHA256 Message Authentication Code
# ============================================================

def compute_hmac(key, data):
    """
    Compute HMAC-SHA256 over data using the given key.

    Used to generate a Message Authentication Code (MAC) that ensures
    data integrity and authenticity of banking transactions.

    Args:
        key: MAC key (K_mac, 16+ bytes)
        data: bytes to authenticate

    Returns:
        32-byte HMAC digest
    """
    return hmac.new(key, data, hashlib.sha256).digest()


def verify_hmac(key, data, received_mac):
    """
    Verify an HMAC-SHA256 MAC.

    Uses constant-time comparison to prevent timing attacks.

    Args:
        key: MAC key (same key used to compute the MAC)
        data: original data that was authenticated
        received_mac: the MAC to verify

    Returns:
        True if MAC is valid, False otherwise
    """
    computed = compute_hmac(key, data)
    return hmac.compare_digest(computed, received_mac)


# ============================================================
# Master Secret & Key Derivation (HKDF-like)
# ============================================================

def generate_master_secret(pre_shared_key, n_atm, n_bank):
    """
    Generate the Master Secret from the pre-shared key and both nonces.

    Master Secret = HMAC-SHA256(K_ps, N_atm || N_bank)

    This combines the pre-shared key with fresh randomness from both
    parties to create a session-specific secret.

    Args:
        pre_shared_key: the pre-shared symmetric key (bytes)
        n_atm: ATM's nonce (bytes)
        n_bank: Bank's nonce (bytes)

    Returns:
        32-byte Master Secret
    """
    combined_nonces = n_atm + n_bank
    return hmac.new(pre_shared_key, combined_nonces, hashlib.sha256).digest()


def derive_keys(master_secret):
    """
    Derive two distinct keys from the Master Secret using HKDF-like expansion.

    K_enc = HMAC-SHA256(Master Secret, b"encryption-key")  -> first 16 bytes
    K_mac = HMAC-SHA256(Master Secret, b"mac-key")          -> first 16 bytes

    Both ATM and bank server derive the same keys from the same Master Secret.

    Args:
        master_secret: 32-byte Master Secret from generate_master_secret()

    Returns:
        (K_enc, K_mac) tuple — each 16 bytes (AES-128 keys)
    """
    k_enc = hmac.new(master_secret, b"encryption-key", hashlib.sha256).digest()[:16]
    k_mac = hmac.new(master_secret, b"mac-key", hashlib.sha256).digest()[:16]
    return k_enc, k_mac


# ============================================================
# Password Hashing
# ============================================================

def hash_password(password):
    """
    Hash a password using SHA-256 for storage.

    Args:
        password: plaintext password string

    Returns:
        Hex-encoded SHA-256 hash string
    """
    return hashlib.sha256(password.encode('utf-8')).hexdigest()


# ============================================================
# Nonce Generation
# ============================================================

def generate_nonce(size=16):
    """Generate a cryptographically secure random nonce (default 128-bit)."""
    return get_random_bytes(size)


def generate_symmetric_key(size=16):
    """Generate a random AES symmetric key (default AES-128 = 16 bytes)."""
    return get_random_bytes(size)


# ============================================================
# Timestamp Utilities (Replay Attack Prevention)
# ============================================================

def generate_timestamp():
    """
    Generate a timestamp as 8 bytes (big-endian integer, seconds since epoch).

    Returns:
        8-byte timestamp (big-endian unsigned long long)
    """
    current_time = int(time.time())
    return struct.pack('>Q', current_time)


def verify_timestamp(ts_bytes, max_age_seconds=60):
    """
    Check whether a timestamp is recent enough (within max_age_seconds).

    Args:
        ts_bytes: 8-byte big-endian timestamp
        max_age_seconds: maximum acceptable age in seconds (default 60)

    Returns:
        True if the timestamp is within the acceptable window, False otherwise
    """
    msg_time = struct.unpack('>Q', ts_bytes)[0]
    current_time = int(time.time())
    age = abs(current_time - msg_time)
    return age <= max_age_seconds


# ============================================================
# Field Packing / Unpacking (length-prefixed binary encoding)
# ============================================================

def pack_fields(*fields):
    """
    Pack multiple byte fields into a single byte string using
    length-prefixed encoding. Safe for arbitrary binary data.

    Format: [4-byte len][field1][4-byte len][field2]...
    """
    result = b''
    for field in fields:
        result += struct.pack('>I', len(field)) + field
    return result


def unpack_fields(data, num_fields):
    """
    Unpack multiple byte fields from a length-prefixed byte string.

    Args:
        data: the packed byte string
        num_fields: how many fields to extract

    Returns:
        List of byte strings (one per field)
    """
    fields = []
    offset = 0
    for _ in range(num_fields):
        field_len = struct.unpack('>I', data[offset:offset+4])[0]
        offset += 4
        fields.append(data[offset:offset+field_len])
        offset += field_len
    return fields


# ============================================================
# Socket Communication Helpers
# ============================================================

def send_data(sock, data):
    """
    Send data over a socket with a 4-byte big-endian length prefix.
    Protocol: [4-byte length][data bytes]
    """
    length_prefix = struct.pack('>I', len(data))
    sock.sendall(length_prefix + data)


def recv_data(sock):
    """
    Receive length-prefixed data from a socket.
    Reads the 4-byte length header, then reads exactly that many bytes.

    Returns:
        The received data bytes, or None if the connection was closed.
    """
    raw_length = recv_exactly(sock, 4)
    if not raw_length:
        return None
    msg_length = struct.unpack('>I', raw_length)[0]
    return recv_exactly(sock, msg_length)


def recv_exactly(sock, num_bytes):
    """
    Read exactly num_bytes from a socket, handling partial reads.

    Returns:
        The complete data, or None if the connection closed prematurely.
    """
    data = b''
    while len(data) < num_bytes:
        chunk = sock.recv(num_bytes - len(data))
        if not chunk:
            return None
        data += chunk
    return data


# ============================================================
# Secure Transaction Helpers
# ============================================================

def encrypt_and_mac(k_enc, k_mac, plaintext_bytes):
    """
    Encrypt data and compute its MAC for a secure transaction message.

    Protocol: ciphertext = E(K_enc, plaintext), mac = HMAC(K_mac, ciphertext)
    Output: pack_fields(ciphertext, mac)

    The MAC is computed over the ciphertext (Encrypt-then-MAC) which is
    the most secure composition of encryption and MAC.

    Args:
        k_enc: encryption key (AES-128)
        k_mac: MAC key (HMAC-SHA256)
        plaintext_bytes: data to protect

    Returns:
        Packed bytes containing [ciphertext, mac]
    """
    ciphertext = aes_encrypt(k_enc, plaintext_bytes)
    mac = compute_hmac(k_mac, ciphertext)
    return pack_fields(ciphertext, mac)


def decrypt_and_verify(k_enc, k_mac, protected_data):
    """
    Verify MAC and decrypt data from a secure transaction message.

    Unpacks [ciphertext, mac], verifies MAC, then decrypts.

    Args:
        k_enc: encryption key (AES-128)
        k_mac: MAC key (HMAC-SHA256)
        protected_data: packed bytes from encrypt_and_mac()

    Returns:
        Decrypted plaintext bytes

    Raises:
        ValueError: if MAC verification fails (data was tampered with)
    """
    ciphertext, mac = unpack_fields(protected_data, 2)
    if not verify_hmac(k_mac, ciphertext, mac):
        raise ValueError("MAC verification failed — data integrity compromised!")
    return aes_decrypt(k_enc, ciphertext)


# ============================================================
# Pretty Printing Helpers
# ============================================================

def bytes_to_hex(b):
    """Convert bytes to a readable uppercase hex string."""
    return b.hex().upper()


def print_separator(title=""):
    """Print a visual separator line with an optional centered title."""
    if title:
        print(f"\n{'='*60}")
        print(f"  {title}")
        print(f"{'='*60}")
    else:
        print(f"{'='*60}")
