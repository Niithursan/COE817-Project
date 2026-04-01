"""
Secure Bank Server for COE817 Project

Multi-threaded bank server with Tkinter GUI that handles ATM client
connections, mutual authentication, and encrypted banking transactions.

Architecture:
  - Socket server listening on 127.0.0.1:5000
  - Each ATM connection handled in a separate thread
  - 3-step mutual authentication protocol with pre-shared keys
  - HKDF key derivation: Master Secret -> K_enc + K_mac
  - All transactions encrypted (AES-CBC) and MAC-protected (HMAC-SHA256)
  - Encrypted audit log stored in audit_log.enc
"""

import os
import json
import socket
import threading
import time
import datetime
import tkinter as tk
from tkinter import ttk, scrolledtext, messagebox

from crypto_utils import (
    aes_encrypt, aes_decrypt,
    generate_nonce, generate_master_secret, derive_keys,
    hash_password,
    encrypt_and_mac, decrypt_and_verify,
    pack_fields, unpack_fields,
    send_data, recv_data,
    verify_timestamp,
    bytes_to_hex, print_separator
)

# configuration
HOST = '127.0.0.1'
PORT = 5000
ACCOUNTS_FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'accounts.json')
AUDIT_LOG_FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'audit_log.enc')

# server-side key for encrypting the audit log file
AUDIT_KEY = bytes.fromhex('0123456789abcdef0123456789abcdef')


# replay attack prevention (MAC Cache)
class ReplayCache:
    """
    Thread-safe cache of recently seen MACs to prevent replay attacks.
    Even within the 60-second timestamp window, each unique MAC may only
    be processed once.  Stale entries are purged automatically.
    """

    def __init__(self, ttl_seconds=60):
        self._cache = {}
        self._lock = threading.Lock()
        self._ttl = ttl_seconds

    def _purge_stale(self):
        """Remove entries older than the TTL."""
        cutoff = time.time() - self._ttl
        stale_keys = [k for k, ts in self._cache.items() if ts < cutoff]
        for k in stale_keys:
            del self._cache[k]

    def check_and_add(self, mac_bytes):
        """Return True if the MAC is new (and record it).  False if duplicate."""
        mac_hex = mac_bytes.hex()
        with self._lock:
            self._purge_stale()
            if mac_hex in self._cache:
                return False
            self._cache[mac_hex] = time.time()
            return True


replay_cache = ReplayCache(ttl_seconds=60)


# account Management
class AccountManager:
    """Thread-safe account manager backed by a JSON file."""

    def __init__(self, filepath):
        self.filepath = filepath
        self.lock = threading.Lock()
        self.accounts = self._load()

    def _load(self):
        """Load accounts from the JSON file."""
        if os.path.exists(self.filepath):
            with open(self.filepath, 'r') as f:
                return json.load(f)
        return {}

    def _save(self):
        """Save accounts to the JSON file."""
        with open(self.filepath, 'w') as f:
            json.dump(self.accounts, f, indent=4)

    def authenticate(self, username, password_hash):
        """Verify username and password hash."""
        with self.lock:
            if username not in self.accounts:
                return False
            return self.accounts[username]['password_hash'] == password_hash

    def get_pre_shared_key(self, username):
        """Get the pre-shared key for a user (as bytes)."""
        with self.lock:
            if username in self.accounts:
                return bytes.fromhex(self.accounts[username]['pre_shared_key'])
        return None

    def get_balance(self, username):
        """Get account balance."""
        with self.lock:
            if username in self.accounts:
                return self.accounts[username]['balance']
        return None

    def deposit(self, username, amount):
        """Deposit funds. Returns new balance or None on failure."""
        with self.lock:
            if username not in self.accounts or amount <= 0:
                return None
            self.accounts[username]['balance'] += amount
            self.accounts[username]['balance'] = round(self.accounts[username]['balance'], 2)
            self._save()
            return self.accounts[username]['balance']

    def withdraw(self, username, amount):
        """Withdraw funds. Returns new balance or None on failure."""
        with self.lock:
            if username not in self.accounts or amount <= 0:
                return None
            if self.accounts[username]['balance'] < amount:
                return -1  # Insufficient funds sentinel
            self.accounts[username]['balance'] -= amount
            self.accounts[username]['balance'] = round(self.accounts[username]['balance'], 2)
            self._save()
            return self.accounts[username]['balance']

    def register(self, username, password, pre_shared_key_hex):
        """Register a new account. Returns True on success."""
        with self.lock:
            if username in self.accounts:
                return False
            self.accounts[username] = {
                'password_hash': hash_password(password),
                'balance': 0.0,
                'pre_shared_key': pre_shared_key_hex
            }
            self._save()
            return True


# encrypted audit log
class AuditLog:
    """Encrypted audit log — all entries are AES-encrypted before storage."""

    def __init__(self, filepath, key):
        self.filepath = filepath
        self.key = key
        self.lock = threading.Lock()

    def log(self, customer_id, action, gui_callback=None):
        """
        Record an audit entry.

        Format: [ Customer ID | Action | Timestamp ]
        The entry is encrypted with the audit key before appending to file.
        """
        timestamp = datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        entry = f"[ {customer_id} | {action} | {timestamp} ]"

        # encrypt the entry
        encrypted_entry = aes_encrypt(self.key, entry.encode('utf-8'))

        with self.lock:
            with open(self.filepath, 'ab') as f:
                # write length-prefixed encrypted entry
                length_bytes = len(encrypted_entry).to_bytes(4, 'big')
                f.write(length_bytes + encrypted_entry)

        # notify GUI
        if gui_callback:
            gui_callback(entry)

    def read_all(self):
        """
        Read and decrypt all audit log entries.
        """
        entries = []
        if not os.path.exists(self.filepath):
            return entries

        with self.lock:
            with open(self.filepath, 'rb') as f:
                data = f.read()

        offset = 0
        while offset < len(data):
            if offset + 4 > len(data):
                break
            entry_len = int.from_bytes(data[offset:offset+4], 'big')
            offset += 4
            if offset + entry_len > len(data):
                break
            encrypted_entry = data[offset:offset+entry_len]
            offset += entry_len
            try:
                decrypted = aes_decrypt(self.key, encrypted_entry)
                entries.append(decrypted.decode('utf-8'))
            except Exception:
                entries.append("[ERROR: Could not decrypt entry]")

        return entries


# client handler (runs in a separate thread per ATM)
def handle_atm_client(conn, addr, account_mgr, audit_log, gui_callback, client_count_callback):
    """
    Handle a single ATM client connection through all phases:
      Phase 1: Mutual authentication (3-step protocol)
      Phase 2: Key derivation
      Phase 3: Transaction processing loop

    Arguments:
        conn: socket connection to the ATM
        addr: client address tuple
        account_mgr: AccountManager instance
        audit_log: AuditLog instance
        gui_callback: function to update the server GUI
        client_count_callback: function to increment/decrement active client count
    """
    client_count_callback(1)
    username = None
    k_enc = None
    k_mac = None

    try:
        gui_callback(f"[CONNECT] ATM connected from {addr[0]}:{addr[1]}")

        # PHASE 1: Mutual Authentication Protocol (3 steps)

        # Step 1: Receive E(K_ps, [username, password_hash, N_atm])
        # The ATM sends credentials + a nonce, encrypted with the
        # pre-shared key. We try all known PSKs to find the matching user.

        auth_request = recv_data(conn)
        if auth_request is None:
            gui_callback(f"[ERROR] No data received from {addr}")
            conn.close()
            return

        # the ATM first sends the username in plaintext so we can look up the PSK
        username_bytes = recv_data(conn)
        if username_bytes is None:
            gui_callback(f"[ERROR] No username received from {addr}")
            conn.close()
            return

        username = username_bytes.decode('utf-8')
        gui_callback(f"[AUTH] Received login attempt from user: {username}")

        # look up the pre-shared key for this user
        psk = account_mgr.get_pre_shared_key(username)
        if psk is None:
            gui_callback(f"[AUTH] FAILED — Unknown user: {username}")
            send_data(conn, b"AUTH_FAIL")
            conn.close()
            return

        # decrypt the authentication request using the pre-shared key
        try:
            auth_plaintext = aes_decrypt(psk, auth_request)
            fields = unpack_fields(auth_plaintext, 2)
            received_password_hash = fields[0].decode('utf-8')
            n_atm = fields[1]
        except Exception as e:
            gui_callback(f"[AUTH] FAILED — Decryption error for {username}: {e}")
            send_data(conn, b"AUTH_FAIL")
            conn.close()
            return

        # verify the password
        if not account_mgr.authenticate(username, received_password_hash):
            gui_callback(f"[AUTH] FAILED — Invalid password for {username}")
            send_data(conn, b"AUTH_FAIL")
            conn.close()
            return

        gui_callback(f"[AUTH] Password verified for {username}")
        gui_callback(f"[AUTH] Received N_atm: {bytes_to_hex(n_atm)}")

        # Step 2: Send E(K_ps, [N_atm, N_bank, "AUTH_OK"])
        # This authenticates the customer to the bank (we verified their password)
        # and provides mutual authentication material (bank's nonce)
        n_bank = generate_nonce(16)
        gui_callback(f"[AUTH] Generated N_bank: {bytes_to_hex(n_bank)}")

        auth_response = pack_fields(n_atm, n_bank, b"AUTH_OK")
        encrypted_response = aes_encrypt(psk, auth_response)
        send_data(conn, encrypted_response)
        gui_callback(f"[AUTH] Sent auth response: E(K_ps, [N_atm, N_bank, AUTH_OK])")

        # Step 3: Receive E(K_ps, [N_bank])
        # ATM proves it has the correct PSK by returning our nonce
        step3_data = recv_data(conn)
        if step3_data is None:
            gui_callback(f"[AUTH] FAILED — No step 3 response from {username}")
            conn.close()
            return

        try:
            step3_plaintext = aes_decrypt(psk, step3_data)
            returned_n_bank = unpack_fields(step3_plaintext, 1)[0]
        except Exception as e:
            gui_callback(f"[AUTH] FAILED — Step 3 decryption error: {e}")
            conn.close()
            return

        if returned_n_bank != n_bank:
            gui_callback(f"[AUTH] FAILED — Nonce mismatch! Bank not authenticated to ATM.")
            send_data(conn, b"AUTH_FAIL")
            conn.close()
            return

        gui_callback(f"[AUTH] Mutual authentication SUCCESSFUL for {username}")
        audit_log.log(username, "LOGIN — Authentication successful", gui_callback)

        # PHASE 2: Key Derivation

        # Both sides independently compute:
        # - Master Secret = HMAC(K_ps, N_atm || N_bank)
        # - K_enc, K_mac = derive_keys(Master Secret)

        master_secret = generate_master_secret(psk, n_atm, n_bank)
        k_enc, k_mac = derive_keys(master_secret)

        gui_callback(f"[KEYS] Master Secret: {bytes_to_hex(master_secret)}")
        gui_callback(f"[KEYS] K_enc: {bytes_to_hex(k_enc)}")
        gui_callback(f"[KEYS] K_mac: {bytes_to_hex(k_mac)}")

        # send confirmation that keys are ready (encrypted with new keys)
        confirm_msg = encrypt_and_mac(k_enc, k_mac, b"KEYS_READY")
        send_data(conn, confirm_msg)
        gui_callback(f"[KEYS] Sent encrypted key confirmation to {username}")

        # PHASE 3: Transaction Processing Loop
        gui_callback(f"[SESSION] Transaction session active for {username}")

        while True:
            # receive encrypted transaction request
            raw_request = recv_data(conn)
            if raw_request is None:
                gui_callback(f"[SESSION] {username} disconnected")
                audit_log.log(username, "LOGOUT — Client disconnected", gui_callback)
                break

            # decrypt and verify MAC
            try:
                request_plaintext = decrypt_and_verify(k_enc, k_mac, raw_request)
            except ValueError as e:
                gui_callback(f"[SECURITY] MAC verification FAILED for {username}: {e}")
                audit_log.log(username, "SECURITY ALERT — MAC verification failed", gui_callback)
                error_response = encrypt_and_mac(k_enc, k_mac,
                    pack_fields(b"ERROR", b"Integrity check failed"))
                send_data(conn, error_response)
                continue

            # --- Replay attack detection (duplicate MAC check) ---
            # extract the MAC tag from the raw request (last field in the packed [ciphertext, mac] structure).
            _, request_mac = unpack_fields(raw_request, 2)
            if not replay_cache.check_and_add(request_mac):
                gui_callback(f"[SECURITY] Replay attack detected from {username}! (Duplicate MAC)")
                audit_log.log(username,
                    "SECURITY ALERT — Replay attack detected (Duplicate MAC)",
                    gui_callback)
                error_response = encrypt_and_mac(k_enc, k_mac,
                    pack_fields(b"ERROR", b"Replay attack detected"))
                send_data(conn, error_response)
                continue

            # unpack: [action, data, timestamp]
            try:
                action_bytes, data_bytes, ts_bytes = unpack_fields(request_plaintext, 3)
            except Exception:
                gui_callback(f"[ERROR] Malformed request from {username}")
                continue

            action = action_bytes.decode('utf-8')
            timestamp_valid = verify_timestamp(ts_bytes, max_age_seconds=60)

            if not timestamp_valid:
                gui_callback(f"[SECURITY] Replay attack detected from {username}!")
                audit_log.log(username, "SECURITY ALERT — Replay attack detected", gui_callback)
                error_response = encrypt_and_mac(k_enc, k_mac,
                    pack_fields(b"ERROR", b"Request expired (possible replay attack)"))
                send_data(conn, error_response)
                continue

            # process the transaction
            response_status = b"OK"
            response_data = b""

            if action == "BALANCE":
                balance = account_mgr.get_balance(username)
                response_data = f"{balance:.2f}".encode('utf-8')
                gui_callback(f"[TXN] {username}: Balance inquiry -> ${balance:.2f}")
                audit_log.log(username, f"BALANCE INQUIRY — Balance: ${balance:.2f}", gui_callback)

            elif action == "DEPOSIT":
                try:
                    amount = float(data_bytes.decode('utf-8'))
                except ValueError:
                    response_status = b"ERROR"
                    response_data = b"Invalid amount"
                    gui_callback(f"[TXN] {username}: Invalid deposit amount")
                else:
                    new_balance = account_mgr.deposit(username, amount)
                    if new_balance is None:
                        response_status = b"ERROR"
                        response_data = b"Deposit failed"
                        gui_callback(f"[TXN] {username}: Deposit failed")
                    else:
                        response_data = f"{new_balance:.2f}".encode('utf-8')
                        gui_callback(f"[TXN] {username}: Deposit ${amount:.2f} -> New balance: ${new_balance:.2f}")
                        audit_log.log(username,
                            f"DEPOSIT — Amount: ${amount:.2f}, New Balance: ${new_balance:.2f}",
                            gui_callback)

            elif action == "WITHDRAW":
                try:
                    amount = float(data_bytes.decode('utf-8'))
                except ValueError:
                    response_status = b"ERROR"
                    response_data = b"Invalid amount"
                    gui_callback(f"[TXN] {username}: Invalid withdrawal amount")
                else:
                    new_balance = account_mgr.withdraw(username, amount)
                    if new_balance is None:
                        response_status = b"ERROR"
                        response_data = b"Withdrawal failed"
                        gui_callback(f"[TXN] {username}: Withdrawal failed")
                    elif new_balance == -1:
                        response_status = b"ERROR"
                        response_data = b"Insufficient funds"
                        gui_callback(f"[TXN] {username}: Insufficient funds for ${amount:.2f} withdrawal")
                        audit_log.log(username,
                            f"WITHDRAW DENIED — Amount: ${amount:.2f}, Insufficient funds",
                            gui_callback)
                    else:
                        response_data = f"{new_balance:.2f}".encode('utf-8')
                        gui_callback(f"[TXN] {username}: Withdraw ${amount:.2f} -> New balance: ${new_balance:.2f}")
                        audit_log.log(username,
                            f"WITHDRAWAL — Amount: ${amount:.2f}, New Balance: ${new_balance:.2f}",
                            gui_callback)

            elif action == "LOGOUT":
                gui_callback(f"[SESSION] {username} logged out")
                audit_log.log(username, "LOGOUT — User logged out", gui_callback)
                logout_response = encrypt_and_mac(k_enc, k_mac,
                    pack_fields(b"OK", b"Logged out successfully"))
                send_data(conn, logout_response)
                break

            else:
                response_status = b"ERROR"
                response_data = f"Unknown action: {action}".encode('utf-8')
                gui_callback(f"[TXN] {username}: Unknown action '{action}'")

            # send encrypted response
            response = encrypt_and_mac(k_enc, k_mac,
                pack_fields(response_status, response_data))
            send_data(conn, response)

    except ConnectionResetError:
        gui_callback(f"[CONNECT] Connection reset by {username or addr}")
        if username:
            audit_log.log(username, "LOGOUT — Connection reset", gui_callback)
    except Exception as e:
        gui_callback(f"[ERROR] Exception handling {username or addr}: {e}")
        if username:
            audit_log.log(username, f"ERROR — {e}", gui_callback)
    finally:
        conn.close()
        client_count_callback(-1)


# server GUI (Tkinter)
class BankServerGUI:
    """Tkinter GUI for the bank server."""

    def __init__(self):
        self.root = tk.Tk()
        self.root.title("COE817 Secure Bank Server")
        self.root.geometry("900x700")
        self.root.configure(bg='#1a1a2e')
        self.root.protocol("WM_DELETE_WINDOW", self.on_close)

        self.server_socket = None
        self.running = False
        self.active_clients = 0
        self.client_lock = threading.Lock()
        self.account_mgr = AccountManager(ACCOUNTS_FILE)
        self.audit_log = AuditLog(AUDIT_LOG_FILE, AUDIT_KEY)

        self._build_ui()
        self._start_server()

    def _build_ui(self):
        """Build the server GUI."""
        style = ttk.Style()
        style.theme_use('clam')

        # configure styles
        style.configure('Title.TLabel', background='#1a1a2e', foreground='#e94560',
                        font=('Consolas', 18, 'bold'))
        style.configure('Status.TLabel', background='#1a1a2e', foreground='#0f3460',
                        font=('Consolas', 11))
        style.configure('Info.TLabel', background='#16213e', foreground='#a8d8ea',
                        font=('Consolas', 10))
        style.configure('Server.TButton', font=('Consolas', 11, 'bold'))

        # --- Title Frame ---
        title_frame = tk.Frame(self.root, bg='#1a1a2e', pady=10)
        title_frame.pack(fill=tk.X)

        ttk.Label(title_frame, text="🏦 COE817 SECURE BANK SERVER",
                  style='Title.TLabel').pack()

        # --- Status Bar ---
        status_frame = tk.Frame(self.root, bg='#16213e', pady=8, padx=15)
        status_frame.pack(fill=tk.X, padx=10)

        self.status_label = ttk.Label(status_frame,
            text=f"● Server listening on {HOST}:{PORT}",
            style='Info.TLabel')
        self.status_label.pack(side=tk.LEFT)

        self.client_count_label = ttk.Label(status_frame,
            text="Active connections: 0",
            style='Info.TLabel')
        self.client_count_label.pack(side=tk.RIGHT)

        # --- Notebook (tabs) ---
        notebook = ttk.Notebook(self.root)
        notebook.pack(fill=tk.BOTH, expand=True, padx=10, pady=5)

        # Tab 1: Activity Log
        log_frame = tk.Frame(notebook, bg='#0f3460')
        notebook.add(log_frame, text="  📋 Activity Log  ")

        self.log_text = scrolledtext.ScrolledText(log_frame,
            bg='#0d1117', fg='#c9d1d9', font=('Consolas', 10),
            insertbackground='#c9d1d9', wrap=tk.WORD,
            relief=tk.FLAT, padx=10, pady=10)
        self.log_text.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        self.log_text.config(state=tk.DISABLED)

        # configure log text tags for colored output
        self.log_text.tag_config('connect', foreground='#58a6ff')
        self.log_text.tag_config('auth', foreground='#f0883e')
        self.log_text.tag_config('keys', foreground='#a371f7')
        self.log_text.tag_config('txn', foreground='#3fb950')
        self.log_text.tag_config('security', foreground='#f85149')
        self.log_text.tag_config('session', foreground='#79c0ff')
        self.log_text.tag_config('error', foreground='#f85149')
        self.log_text.tag_config('audit', foreground='#d2a8ff')
        self.log_text.tag_config('info', foreground='#8b949e')

        # Tab 2: Audit Log Viewer
        audit_frame = tk.Frame(notebook, bg='#0f3460')
        notebook.add(audit_frame, text="  🔐 Audit Log  ")

        btn_frame = tk.Frame(audit_frame, bg='#0f3460', pady=8)
        btn_frame.pack(fill=tk.X, padx=10)

        decrypt_btn = tk.Button(btn_frame, text="🔓 Decrypt & View Audit Log",
            bg='#238636', fg='white', font=('Consolas', 11, 'bold'),
            activebackground='#2ea043', relief=tk.FLAT, padx=20, pady=8,
            cursor='hand2', command=self._show_audit_log)
        decrypt_btn.pack(side=tk.LEFT, padx=5)

        clear_btn = tk.Button(btn_frame, text="🗑 Clear Audit Log",
            bg='#da3633', fg='white', font=('Consolas', 11, 'bold'),
            activebackground='#f85149', relief=tk.FLAT, padx=20, pady=8,
            cursor='hand2', command=self._clear_audit_log)
        clear_btn.pack(side=tk.LEFT, padx=5)

        self.audit_text = scrolledtext.ScrolledText(audit_frame,
            bg='#0d1117', fg='#c9d1d9', font=('Consolas', 10),
            insertbackground='#c9d1d9', wrap=tk.WORD,
            relief=tk.FLAT, padx=10, pady=10)
        self.audit_text.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        self.audit_text.config(state=tk.DISABLED)

        # Tab 3: Accounts
        accounts_frame = tk.Frame(notebook, bg='#0f3460')
        notebook.add(accounts_frame, text="  👥 Accounts  ")

        refresh_btn = tk.Button(accounts_frame, text="🔄 Refresh Accounts",
            bg='#1f6feb', fg='white', font=('Consolas', 11, 'bold'),
            activebackground='#388bfd', relief=tk.FLAT, padx=20, pady=8,
            cursor='hand2', command=self._show_accounts)
        refresh_btn.pack(pady=10)

        self.accounts_text = scrolledtext.ScrolledText(accounts_frame,
            bg='#0d1117', fg='#c9d1d9', font=('Consolas', 10),
            insertbackground='#c9d1d9', wrap=tk.WORD,
            relief=tk.FLAT, padx=10, pady=10)
        self.accounts_text.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        self.accounts_text.config(state=tk.DISABLED)

        self._show_accounts()

    def _log(self, message):
        """Thread-safe logging to the GUI activity log."""
        def _update():
            self.log_text.config(state=tk.NORMAL)

            # determine tag based on message prefix
            tag = 'info'
            if '[CONNECT]' in message:
                tag = 'connect'
            elif '[AUTH]' in message:
                tag = 'auth'
            elif '[KEYS]' in message:
                tag = 'keys'
            elif '[TXN]' in message:
                tag = 'txn'
            elif '[SECURITY]' in message:
                tag = 'security'
            elif '[SESSION]' in message:
                tag = 'session'
            elif '[ERROR]' in message:
                tag = 'error'
            elif '[' in message and '|' in message:
                tag = 'audit'

            timestamp = datetime.datetime.now().strftime('%H:%M:%S')
            self.log_text.insert(tk.END, f"[{timestamp}] {message}\n", tag)
            self.log_text.see(tk.END)
            self.log_text.config(state=tk.DISABLED)

        self.root.after(0, _update)

    def _show_audit_log(self):
        """Decrypt and display the audit log."""
        entries = self.audit_log.read_all()
        self.audit_text.config(state=tk.NORMAL)
        self.audit_text.delete('1.0', tk.END)

        if not entries:
            self.audit_text.insert(tk.END, "No audit log entries found.\n")
        else:
            self.audit_text.insert(tk.END, f"{'='*60}\n")
            self.audit_text.insert(tk.END, f"  DECRYPTED AUDIT LOG — {len(entries)} entries\n")
            self.audit_text.insert(tk.END, f"{'='*60}\n\n")
            for i, entry in enumerate(entries, 1):
                self.audit_text.insert(tk.END, f"  {i:3d}. {entry}\n")
            self.audit_text.insert(tk.END, f"\n{'='*60}\n")

        self.audit_text.config(state=tk.DISABLED)

    def _clear_audit_log(self):
        """Clear the audit log file."""
        if messagebox.askyesno("Confirm", "Clear the entire audit log?"):
            if os.path.exists(AUDIT_LOG_FILE):
                os.remove(AUDIT_LOG_FILE)
            self.audit_text.config(state=tk.NORMAL)
            self.audit_text.delete('1.0', tk.END)
            self.audit_text.insert(tk.END, "Audit log cleared.\n")
            self.audit_text.config(state=tk.DISABLED)
            self._log("[INFO] Audit log cleared by administrator")

    def _show_accounts(self):
        """Display current account information."""
        self.account_mgr.accounts = self.account_mgr._load()
        self.accounts_text.config(state=tk.NORMAL)
        self.accounts_text.delete('1.0', tk.END)

        self.accounts_text.insert(tk.END, f"{'='*60}\n")
        self.accounts_text.insert(tk.END, f"  REGISTERED ACCOUNTS\n")
        self.accounts_text.insert(tk.END, f"{'='*60}\n\n")

        for username, info in self.account_mgr.accounts.items():
            self.accounts_text.insert(tk.END, f"  👤 Username:    {username}\n")
            self.accounts_text.insert(tk.END, f"     Balance:     ${info['balance']:.2f}\n")
            self.accounts_text.insert(tk.END, f"     PSK:         {info['pre_shared_key'][:16]}...\n")
            self.accounts_text.insert(tk.END, f"     Pass Hash:   {info['password_hash'][:16]}...\n")
            self.accounts_text.insert(tk.END, f"\n")

        self.accounts_text.insert(tk.END, f"{'='*60}\n")
        self.accounts_text.config(state=tk.DISABLED)

    def _start_server(self):
        """Start the server socket in a background thread."""
        self.running = True
        server_thread = threading.Thread(target=self._server_loop, daemon=True)
        server_thread.start()

    def update_client_count(self, delta):
        """Thread-safe update of the active client connection count."""
        with self.client_lock:
            self.active_clients += delta
            count = self.active_clients
        self.root.after(0, lambda:
            self.client_count_label.config(text=f"Active connections: {count}"))

    def _server_loop(self):
        """Main server loop — accept connections and spawn handler threads."""
        self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

        try:
            self.server_socket.bind((HOST, PORT))
        except OSError as e:
            self._log(f"[ERROR] Cannot bind to {HOST}:{PORT}: {e}")
            return

        self.server_socket.listen(5)
        self.server_socket.settimeout(1.0)  # allow periodic checking of self.running

        self._log(f"[INFO] Server started — listening on {HOST}:{PORT}")
        self._log(f"[INFO] Waiting for ATM client connections...")

        while self.running:
            try:
                conn, addr = self.server_socket.accept()

                # spawn a handler thread for this ATM client
                handler = threading.Thread(
                    target=handle_atm_client,
                    args=(conn, addr, self.account_mgr, self.audit_log,
                          self._log, self.update_client_count),
                    daemon=True
                )
                handler.start()

            except socket.timeout:
                continue
            except OSError:
                break

    def on_close(self):
        """clean shutdown."""
        self.running = False
        if self.server_socket:
            try:
                self.server_socket.close()
            except Exception:
                pass
        self.root.destroy()

    def run(self):
        """start the Tkinter event loop."""
        self.root.mainloop()


# main Entry Point
if __name__ == '__main__':
    print_separator("COE817 SECURE BANK SERVER")
    print(f"  Starting server on {HOST}:{PORT}")
    print(f"  Accounts file: {ACCOUNTS_FILE}")
    print(f"  Audit log file: {AUDIT_LOG_FILE}")
    print_separator()

    app = BankServerGUI()
    app.run()
