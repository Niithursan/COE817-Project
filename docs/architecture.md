This document describes the system modules, responsibilities, and how they interact.

---

## High-level architecture

```mermaid
graph TD
  A1[ATM Client (Tkinter)\n atm_client.py] -->|TCP 127.0.0.1:5000\nlength-prefixed frames| S[Bank Server (Tkinter)\n bank_server.py]
  A2[ATM Client #2] --> S
  A3[ATM Client #3] --> S

  S --> ACC[AccountManager\naccounts.json]
  S --> AUD[AuditLog\n audit_log.enc (encrypted)]
  S --> RC[ReplayCache\n(duplicate MAC detection)]
  A1 --> CU[crypto_utils.py]
  S --> CU
```

---

## Modules

### 1) `atm_client.py` — ATM Client GUI + protocol engine
**Primary responsibilities**
- Provide GUI:
  - login screen (username/password)
  - transaction screen (balance, deposit, withdraw, logout)
  - protocol log output
- Establish TCP connection to the server
- Run mutual authentication protocol
- Derive session keys
- Send encrypted+MAC’d transaction requests and process responses

**Key components**
- `ATMClientGUI` class (Tkinter UI)
- `_authenticate(username, password)`:
  - Phase 1 mutual authentication using PSK + nonces
  - Phase 2 derive `k_enc`, `k_mac`
  - validates server key confirmation message
- `_send_transaction(action, data)`:
  - builds request `pack_fields(action, data, timestamp)`
  - wraps with `encrypt_and_mac(k_enc, k_mac, ...)`

**Important configuration**
- `PRE_SHARED_KEYS` dict must match `accounts.json` server-side PSKs.

---

### 2) `bank_server.py` — Bank server + GUI + multi-client worker threads
**Primary responsibilities**
- Listen on TCP socket
- Accept client connections and handle each in a new thread
- Authenticate clients using PSK protocol
- Derive per-connection session keys
- Process transactions (deposit/withdraw/balance/logout)
- Enforce replay defenses
- Write encrypted audit log
- Provide admin GUI for visibility (activity log, audit log viewer)

**Key components**
- `ReplayCache`: thread-safe TTL cache for duplicate MAC detection
- `AccountManager`:
  - loads/saves `accounts.json`
  - `authenticate()`, `deposit()`, `withdraw()`, `get_balance()`
  - `register()` exists but is not wired into client protocol/UI yet
- `AuditLog`:
  - encrypts each entry before appending to `audit_log.enc`
  - supports decrypt+view (`read_all()`)
- `handle_atm_client(conn, addr, ...)`:
  - Phase 1 auth
  - Phase 2 key derivation + key confirmation
  - Phase 3 transaction loop
- `BankServerGUI`: Tkinter UI for server visibility and audit log viewing

---

### 3) `crypto_utils.py` — cryptographic + protocol utility layer
**Primary responsibilities**
- Symmetric crypto:
  - AES-CBC with random IV + PKCS7 padding (`aes_encrypt`, `aes_decrypt`)
- Integrity:
  - HMAC-SHA256 (`compute_hmac`, `verify_hmac`)
- Master Secret + key derivation:
  - `generate_master_secret(psk, n_atm, n_bank)`
  - `derive_keys(master_secret)` → `(k_enc, k_mac)`
- Replay helpers:
  - timestamps (`generate_timestamp`, `verify_timestamp`)
- Encoding/framing:
  - `pack_fields` / `unpack_fields` (length-prefixed binary)
  - `send_data` / `recv_data` (length-prefixed socket frames)
- Secure message wrappers:
  - `encrypt_and_mac`
  - `decrypt_and_verify`

---

## Concurrency / threading model
- Server is multi-threaded:
  - main thread accepts new connections
  - each ATM connection runs `handle_atm_client()` in its own thread
- Account operations and audit log are protected by locks:
  - `AccountManager.lock`
  - `AuditLog.lock`
- Replay cache has its own lock:
  - `ReplayCache._lock`

---

## Data storage
- `accounts.json` (plaintext JSON):
  - username → `password_hash`, `balance`, `pre_shared_key`
- `audit_log.enc` (encrypted binary):
  - length-prefixed encrypted entries
  - each entry encrypted using `AUDIT_KEY` on server

---

## Security boundary notes
- Session keys `k_enc/k_mac` are per-connection (derived fresh each login).
- Transaction messages are confidentiality + integrity protected end-to-end.
- Replay protection uses:
  - timestamp window (default 60s)
  - duplicate MAC cache (TTL 60s)
- Registration is the main incomplete “product” feature (accounts are pre-seeded).