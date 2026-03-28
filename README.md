# COE817 Secure Banking System

A secure banking system with one bank server and three ATM clients, built for the COE817 Network Security course project.

## Features

- **3-Step Mutual Authentication** using pre-shared symmetric keys and nonces
- **HKDF Key Derivation** — Master Secret → `K_enc` (encryption) + `K_mac` (MAC)
- **Hardened Replay Protection** — Combines 60-second timestamp verification with a `thread-safe MAC Cache` on the server to prevent any intercepted message from being re-processed.
- **Encrypted Transactions** — AES-CBC with Encrypt-then-MAC (HMAC-SHA256)
- **Encrypted Audit Log** — all actions logged with `[Customer ID | Action | Timestamp]` format, encrypted at rest
- **Tkinter GUIs** — graphical interfaces for both the bank server and ATM clients
- **Multi-threaded Server** — handles multiple ATM clients concurrently

## Project Structure

```
Project/
├── crypto_utils.py   # Cryptographic primitives (AES, HMAC, HKDF, socket helpers)
├── bank_server.py    # Multi-threaded bank server with Tkinter GUI
├── atm_client.py     # ATM client with Tkinter GUI
├── accounts.json     # Pre-seeded user accounts
└── README.md
```

## Prerequisites

- Python 3.10+
- `pycryptodome`

```bash
pip install pycryptodome
```

## How to Run

### 1. Start the Bank Server

```bash
python bank_server.py
```

The server GUI will appear, listening on `127.0.0.1:5000`.

### 2. Start ATM Clients (up to 3)

Open separate terminals and run:

```bash
python atm_client.py
```

### 3. Login & Transact

Use any of the pre-registered accounts:

| Username  | Password     | Starting Balance |
|-----------|--------------|------------------|
| alice     | hello        | $1,000.00        |
| bob       | password     | $2,500.00        |
| charlie   | charlie123   | $500.00          |

## Security Protocol

```
ATM                                          Bank Server
 │                                                │
 │──── username + E(K_ps, [pw_hash, N_atm]) ─────►│  Step 1: Customer auth
 │                                                │
 │◄──── E(K_ps, [N_atm, N_bank, AUTH_OK]) ────────│  Step 2: Bank auth
 │                                                │
 │──── E(K_ps, [N_bank]) ────────────────────────►│  Step 3: Mutual auth confirmed
 │                                                │
 │  Both derive: MS = HMAC(K_ps, N_atm || N_bank) │
 │  K_enc = HKDF(MS, "encryption-key")            │
 │  K_mac = HKDF(MS, "mac-key")                   │
 │                                                │
 │──── E(K_enc, [action, data, ts]) + MAC ────────►│  Encrypted transaction
 │◄──── E(K_enc, [status, data]) + MAC ───────────│  Encrypted response
```

## Demonstration

1. Start the bank server, then launch 3 ATM clients
2. Log in as `alice` → deposit $500, withdraw $200, check balance
3. Log in as `bob` → perform 2–3 transactions
4. On the server GUI, click **"Decrypt & View Audit Log"** to verify all actions are recorded
5. Inspect `audit_log.enc` on disk to confirm it is encrypted (not human-readable)
