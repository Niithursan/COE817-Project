"""
Secure ATM Client for COE817 Project

Tkinter-based ATM client that connects to the bank server, performs
mutual authentication, and enables secure banking transactions.

Workflow:
  Phase 1 (Mutual Authentication):
    Step 1: ATM -> Bank: username (plaintext) + E(K_ps, [password_hash, N_atm])
    Step 2: Bank -> ATM: E(K_ps, [N_atm, N_bank, "AUTH_OK"])
    Step 3: ATM -> Bank: E(K_ps, [N_bank])

  Phase 2 (Key Derivation):
    Master Secret = HMAC(K_ps, N_atm || N_bank)
    K_enc = HKDF(MS, "encryption-key")
    K_mac = HKDF(MS, "mac-key")

  Phase 3 (Transactions):
    Request:  E(K_enc, [action, data, timestamp]) + MAC(K_mac, ciphertext)
    Response: E(K_enc, [status, data]) + MAC(K_mac, ciphertext)
"""

import socket
import threading
import tkinter as tk
import datetime

from crypto_utils import (
    aes_encrypt, aes_decrypt,
    generate_nonce, generate_master_secret, derive_keys,
    hash_password,
    encrypt_and_mac, decrypt_and_verify,
    pack_fields, unpack_fields,
    send_data, recv_data,
    generate_timestamp,
    bytes_to_hex, print_separator
)

# configuration
HOST = '127.0.0.1'
PORT = 5000

# pre-shared keys for each user
PRE_SHARED_KEYS = {
    'alice':   bytes.fromhex('a1b2c3d4e5f60718a1b2c3d4e5f60718'),
    'bob':     bytes.fromhex('18071f6e5d4c3b2a18071f6e5d4c3b2a'),
    'charlie': bytes.fromhex('deadbeefcafe1234deadbeefcafe1234'),
}

# ATM client GUI
class ATMClientGUI:
    """Full ATM client with login screen, transaction screen, and protocol log."""

    def __init__(self):
        self.root = tk.Tk()
        self.root.title("COE817 ATM Client")
        self.root.geometry("750x650")
        self.root.configure(bg='#0d1117')
        self.root.protocol("WM_DELETE_WINDOW", self.on_close)

        # connection state
        self.sock = None
        self.username = None
        self.k_enc = None
        self.k_mac = None
        self.authenticated = False
        self.txn_lock = threading.Lock()

        self._build_login_screen()

    # LOGIN SCREEN
    def _build_login_screen(self, message=""):
        """Build the login UI."""
        # clear any existing widgets
        for widget in self.root.winfo_children():
            widget.destroy()

        self.root.configure(bg='#0d1117')

        # main container with centered content
        container = tk.Frame(self.root, bg='#0d1117')
        container.place(relx=0.5, rely=0.5, anchor='center')

        # ATM logo
        tk.Label(container, text="🏧", font=('Segoe UI Emoji', 48),
                 bg='#0d1117', fg='white').pack(pady=(0, 5))

        tk.Label(container, text="SECURE ATM CLIENT",
                 font=('Consolas', 20, 'bold'), bg='#0d1117',
                 fg='#58a6ff').pack(pady=(0, 5))

        tk.Label(container, text="COE817 Network Security Project",
                 font=('Consolas', 10), bg='#0d1117',
                 fg='#8b949e').pack(pady=(0, 30))

        # login form frame
        form_frame = tk.Frame(container, bg='#161b22', padx=40, pady=30,
                              highlightbackground='#30363d', highlightthickness=1)
        form_frame.pack()

        tk.Label(form_frame, text="Username", font=('Consolas', 11),
                 bg='#161b22', fg='#c9d1d9').pack(anchor='w', pady=(0, 5))

        self.username_entry = tk.Entry(form_frame, font=('Consolas', 12),
            bg='#0d1117', fg='#c9d1d9', insertbackground='#c9d1d9',
            relief=tk.FLAT, width=28, highlightbackground='#30363d',
            highlightthickness=1)
        self.username_entry.pack(pady=(0, 15), ipady=6)

        tk.Label(form_frame, text="Password", font=('Consolas', 11),
                 bg='#161b22', fg='#c9d1d9').pack(anchor='w', pady=(0, 5))

        self.password_entry = tk.Entry(form_frame, font=('Consolas', 12),
            bg='#0d1117', fg='#c9d1d9', insertbackground='#c9d1d9',
            relief=tk.FLAT, width=28, show='●',
            highlightbackground='#30363d', highlightthickness=1)
        self.password_entry.pack(pady=(0, 20), ipady=6)

        self.login_btn = tk.Button(form_frame, text="🔐  AUTHENTICATE & LOGIN",
            bg='#238636', fg='white', font=('Consolas', 12, 'bold'),
            activebackground='#2ea043', relief=tk.FLAT, padx=20, pady=10,
            cursor='hand2', command=self._do_login)
        self.login_btn.pack(fill=tk.X)

        # status text
        self.login_status = tk.Label(container, text="",
            font=('Consolas', 10), bg='#0d1117', fg='#f85149')
        self.login_status.pack(pady=(15, 0))

        if message:
            color = '#3fb950' if message.startswith('✅') else '#f85149'
            self.login_status.config(text=message, fg=color)

        # hint
        tk.Label(container, text="Default accounts: alice/hello, bob/password, charlie/charlie123",
                 font=('Consolas', 9), bg='#0d1117', fg='#484f58').pack(pady=(10, 0))

        # bind enter key
        self.password_entry.bind('<Return>', lambda e: self._do_login())
        self.username_entry.bind('<Return>', lambda e: self.password_entry.focus())
        self.username_entry.focus()

    def _do_login(self):
        """Perform the login and authentication protocol."""
        username = self.username_entry.get().strip().lower()
        password = self.password_entry.get().strip()

        if not username or not password:
            self.login_status.config(text="Please enter both username and password")
            return

        if username not in PRE_SHARED_KEYS:
            self.login_status.config(text=f"Unknown user: {username}")
            return

        self.login_btn.config(state=tk.DISABLED, text="Authenticating...")
        self.login_status.config(text="Connecting to bank server...", fg='#58a6ff')
        self.root.update()

        # run authentication in a background thread
        auth_thread = threading.Thread(
            target=self._authenticate,
            args=(username, password),
            daemon=True
        )
        auth_thread.start()

    def _authenticate(self, username, password):
        """
        Run the 3-step mutual authentication protocol.
        Called in a background thread.
        """
        try:
            # connect to the bank server
            self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.sock.connect((HOST, PORT))

            psk = PRE_SHARED_KEYS[username]
            password_hash = hash_password(password)

            # STEP 1: send E(K_ps, [password_hash, N_atm]) + username
            n_atm = generate_nonce(16)

            auth_plaintext = pack_fields(
                password_hash.encode('utf-8'),
                n_atm
            )
            auth_ciphertext = aes_encrypt(psk, auth_plaintext)

            # send encrypted auth request first, then username in plaintext
            send_data(self.sock, auth_ciphertext)
            send_data(self.sock, username.encode('utf-8'))

            self._update_login_status("Step 1: Sent credentials + nonce", '#58a6ff')

            # STEP 2: receive E(K_ps, [N_atm, N_bank, "AUTH_OK"])
            response_data = recv_data(self.sock)
            if response_data is None:
                self._auth_failed("Connection lost")
                return

            # check for plaintext error response
            if response_data == b"AUTH_FAIL":
                self._auth_failed("Authentication failed — invalid credentials")
                return

            # decrypt the response with our PSK
            try:
                response_plaintext = aes_decrypt(psk, response_data)
                returned_n_atm, n_bank, auth_status = unpack_fields(response_plaintext, 3)
            except Exception as e:
                self._auth_failed(f"Decryption failed: {e}")
                return

            # verify the bank returned our nonce correctly
            if returned_n_atm != n_atm:
                self._auth_failed("Nonce mismatch — possible MITM attack!")
                return

            if auth_status != b"AUTH_OK":
                self._auth_failed("Authentication rejected by server")
                return

            self._update_login_status("Step 2: Bank authenticated ✓", '#3fb950')

            # STEP 3: Send E(K_ps, [N_bank]) to prove we have the PSK
            step3_plaintext = pack_fields(n_bank)
            step3_ciphertext = aes_encrypt(psk, step3_plaintext)
            send_data(self.sock, step3_ciphertext)

            self._update_login_status("Step 3: Mutual auth complete ✓", '#3fb950')

            # KEY DERIVATION
            master_secret = generate_master_secret(psk, n_atm, n_bank)
            self.k_enc, self.k_mac = derive_keys(master_secret)

            # wait for server's key confirmation
            key_confirm = recv_data(self.sock)
            if key_confirm is None:
                self._auth_failed("No key confirmation received")
                return

            try:
                confirm_msg = decrypt_and_verify(self.k_enc, self.k_mac, key_confirm)
                if confirm_msg != b"KEYS_READY":
                    self._auth_failed("Key confirmation mismatch")
                    return
            except ValueError:
                self._auth_failed("Key confirmation MAC failed")
                return

            # authentication successful!
            self.username = username
            self.authenticated = True

            self._update_login_status("✅ Authenticated! Keys derived.", '#3fb950')

            # transition to transaction screen
            self.root.after(500, self._build_transaction_screen)

        except ConnectionRefusedError:
            self._auth_failed("Cannot connect — is the bank server running?")
        except Exception as e:
            self._auth_failed(f"Error: {e}")

    def _auth_failed(self, message):
        """Handle authentication failure."""
        if self.sock:
            try:
                self.sock.close()
            except Exception:
                pass
            self.sock = None

        self.root.after(0, lambda: [
            self.login_status.config(text=f"❌ {message}", fg='#f85149'),
            self.login_btn.config(state=tk.NORMAL, text="🔐  AUTHENTICATE & LOGIN")
        ])

    def _update_login_status(self, text, color):
        """Thread-safe status update."""
        self.root.after(0, lambda: self.login_status.config(text=text, fg=color))


    # TRANSACTION SCREEN
    def _build_transaction_screen(self):
        """build the main banking transaction UI."""
        for widget in self.root.winfo_children():
            widget.destroy()

        self.root.configure(bg='#0d1117')

        # Header
        header = tk.Frame(self.root, bg='#161b22', pady=12, padx=20)
        header.pack(fill=tk.X)

        tk.Label(header, text=f"🏧 ATM — Welcome, {self.username.title()}",
                 font=('Consolas', 16, 'bold'), bg='#161b22',
                 fg='#58a6ff').pack(side=tk.LEFT)

        logout_btn = tk.Button(header, text="Logout",
            bg='#da3633', fg='white', font=('Consolas', 10, 'bold'),
            relief=tk.FLAT, padx=15, pady=4, cursor='hand2',
            command=self._do_logout)
        logout_btn.pack(side=tk.RIGHT)

        self.conn_status = tk.Label(header, text="● Connected & Authenticated",
            font=('Consolas', 9), bg='#161b22', fg='#3fb950')
        self.conn_status.pack(side=tk.RIGHT, padx=15)

        # Main content
        main = tk.Frame(self.root, bg='#0d1117')
        main.pack(fill=tk.BOTH, expand=True, padx=15, pady=10)

        # Left panel: Actions
        left = tk.Frame(main, bg='#161b22', padx=20, pady=20,
                        highlightbackground='#30363d', highlightthickness=1)
        left.pack(side=tk.LEFT, fill=tk.Y, padx=(0, 10))

        tk.Label(left, text="TRANSACTIONS",
                 font=('Consolas', 13, 'bold'), bg='#161b22',
                 fg='#c9d1d9').pack(pady=(0, 20))

        # Balance inquiry
        balance_btn = tk.Button(left, text="💰  Check Balance",
            bg='#1f6feb', fg='white', font=('Consolas', 11, 'bold'),
            activebackground='#388bfd', relief=tk.FLAT, padx=20, pady=10,
            cursor='hand2', width=20, command=self._do_balance)
        balance_btn.pack(pady=5, fill=tk.X)

        # Separator
        tk.Frame(left, bg='#30363d', height=1).pack(fill=tk.X, pady=15)

        # Amount input
        tk.Label(left, text="Amount ($)", font=('Consolas', 11),
                 bg='#161b22', fg='#c9d1d9').pack(anchor='w', pady=(0, 5))

        self.amount_entry = tk.Entry(left, font=('Consolas', 14),
            bg='#0d1117', fg='#3fb950', insertbackground='#3fb950',
            relief=tk.FLAT, width=20, justify='right',
            highlightbackground='#30363d', highlightthickness=1)
        self.amount_entry.pack(ipady=8, fill=tk.X, pady=(0, 15))

        # Deposit button
        deposit_btn = tk.Button(left, text="📥  Deposit",
            bg='#238636', fg='white', font=('Consolas', 11, 'bold'),
            activebackground='#2ea043', relief=tk.FLAT, padx=20, pady=10,
            cursor='hand2', width=20, command=self._do_deposit)
        deposit_btn.pack(pady=5, fill=tk.X)

        # Withdraw button
        withdraw_btn = tk.Button(left, text="📤  Withdraw",
            bg='#f0883e', fg='white', font=('Consolas', 11, 'bold'),
            activebackground='#d29922', relief=tk.FLAT, padx=20, pady=10,
            cursor='hand2', width=20, command=self._do_withdraw)
        withdraw_btn.pack(pady=5, fill=tk.X)

        # Result display
        tk.Frame(left, bg='#30363d', height=1).pack(fill=tk.X, pady=15)

        self.result_label = tk.Label(left, text="",
            font=('Consolas', 12, 'bold'), bg='#161b22', fg='#3fb950',
            wraplength=250, justify='center')
        self.result_label.pack(pady=5)

        # Right panel: Protocol Log
        right = tk.Frame(main, bg='#161b22',
                         highlightbackground='#30363d', highlightthickness=1)
        right.pack(side=tk.RIGHT, fill=tk.BOTH, expand=True)

        tk.Label(right, text="📋 SECURITY PROTOCOL LOG",
                 font=('Consolas', 11, 'bold'), bg='#161b22',
                 fg='#c9d1d9').pack(pady=(10, 5))

        self.proto_log = tk.Text(right,
            bg='#0d1117', fg='#8b949e', font=('Consolas', 9),
            insertbackground='#c9d1d9', wrap=tk.WORD,
            relief=tk.FLAT, padx=10, pady=10)
        self.proto_log.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        self.proto_log.config(state=tk.DISABLED)

        # Configure tags
        self.proto_log.tag_config('success', foreground='#3fb950')
        self.proto_log.tag_config('error', foreground='#f85149')
        self.proto_log.tag_config('info', foreground='#58a6ff')
        self.proto_log.tag_config('crypto', foreground='#a371f7')
        self.proto_log.tag_config('txn', foreground='#f0883e')

        # Log the authentication details
        self._proto_log("=== Authentication Complete ===", 'success')
        self._proto_log(f"User: {self.username}", 'info')
        self._proto_log(f"K_enc: {bytes_to_hex(self.k_enc)}", 'crypto')
        self._proto_log(f"K_mac: {bytes_to_hex(self.k_mac)}", 'crypto')
        self._proto_log("All transactions are encrypted (AES-CBC)", 'crypto')
        self._proto_log("All transactions are MAC-protected (HMAC-SHA256)", 'crypto')
        self._proto_log("=" * 40, 'info')

    def _proto_log(self, message, tag='info'):
        """Add a message to the protocol log."""
        def _update():
            self.proto_log.config(state=tk.NORMAL)
            timestamp = datetime.datetime.now().strftime('%H:%M:%S')
            self.proto_log.insert(tk.END, f"[{timestamp}] {message}\n", tag)
            self.proto_log.see(tk.END)
            self.proto_log.config(state=tk.DISABLED)
        self.root.after(0, _update)

    def _send_transaction(self, action, data=""):
        """
        Send an encrypted transaction to the bank server and return the response.

        Workflow:
          Request:  encrypt_and_mac(K_enc, K_mac, pack_fields(action, data, timestamp))
          Response: decrypt_and_verify(K_enc, K_mac, response) -> [status, data]
        """
        if not self.authenticated or not self.sock:
            return None, "Not authenticated"

        try:
            # build and encrypt the request
            timestamp = generate_timestamp()
            request_plaintext = pack_fields(
                action.encode('utf-8'),
                data.encode('utf-8'),
                timestamp
            )
            encrypted_request = encrypt_and_mac(self.k_enc, self.k_mac, request_plaintext)

            self._proto_log(f"→ Sending: {action} {data}", 'txn')
            self._proto_log(f"  Encrypted payload: {len(encrypted_request)} bytes", 'crypto')

            # acquire lock to prevent concurrent socket access from multiple transaction threads (deposit/withdraw/balance).
            with self.txn_lock:
                # send the request
                send_data(self.sock, encrypted_request)

                # receive and decrypt the response
                raw_response = recv_data(self.sock)

            if raw_response is None:
                self._proto_log("Server closed the connection.", 'error')
                self._handle_disconnect()
                return None, "Connection to bank server lost."

            response_plaintext = decrypt_and_verify(self.k_enc, self.k_mac, raw_response)
            status, response_data = unpack_fields(response_plaintext, 2)

            status_str = status.decode('utf-8')
            data_str = response_data.decode('utf-8')

            self._proto_log(f"← Response: {status_str} — {data_str}", 'success')
            self._proto_log(f"  MAC verified ✓", 'crypto')

            return status_str, data_str

        except (ConnectionResetError, BrokenPipeError,
                ConnectionAbortedError, EOFError, OSError) as e:
            self._proto_log(f"Network error: {e}", 'error')
            self._handle_disconnect()
            return None, "Connection to bank server lost."
        except ValueError as e:
            self._proto_log(f"MAC VERIFICATION FAILED: {e}", 'error')
            return None, "Data integrity compromised!"
        except Exception as e:
            self._proto_log(f"Error: {e}", 'error')
            return None, str(e)

    def _handle_disconnect(self):
        """Clean up client state after a network disconnect and return to login."""
        if self.sock:
            try:
                self.sock.close()
            except Exception:
                pass
        self.sock = None
        self.authenticated = False
        self.k_enc = None
        self.k_mac = None
        self.username = None
        self.root.after(0, lambda: self._build_login_screen(
            "❌ Disconnected: Bank server offline or connection lost"))

    def _do_balance(self):
        """Handle balance inquiry."""
        def _run():
            status, data = self._send_transaction("BALANCE")
            if status == "OK":
                self.root.after(0, lambda: self.result_label.config(
                    text=f"Balance: ${data}", fg='#3fb950'))
            else:
                self.root.after(0, lambda: self.result_label.config(
                    text=f"Error: {data}", fg='#f85149'))

        threading.Thread(target=_run, daemon=True).start()

    def _do_amount_transaction(self, action, verb):
        """Handle a deposit or withdrawal transaction."""
        amount = self.amount_entry.get().strip()
        if not amount:
            self.result_label.config(text="Enter an amount", fg='#f85149')
            return
        try:
            float(amount)
        except ValueError:
            self.result_label.config(text="Invalid amount", fg='#f85149')
            return

        def _run():
            status, data = self._send_transaction(action, amount)
            if status == "OK":
                self.root.after(0, lambda: [
                    self.result_label.config(
                        text=f"{verb} ${amount}\nNew Balance: ${data}", fg='#3fb950'),
                    self.amount_entry.delete(0, tk.END)
                ])
            else:
                self.root.after(0, lambda: self.result_label.config(
                    text=f"Error: {data}", fg='#f85149'))

        threading.Thread(target=_run, daemon=True).start()

    def _do_deposit(self):
        """Handle deposit."""
        self._do_amount_transaction("DEPOSIT", "Deposited")

    def _do_withdraw(self):
        """Handle withdrawal."""
        self._do_amount_transaction("WITHDRAW", "Withdrew")

    def _do_logout(self):
        """Handle logout."""
        def _run():
            try:
                self._send_transaction("LOGOUT")
            except Exception:
                pass
            finally:
                if self.sock:
                    try:
                        self.sock.close()
                    except Exception:
                        pass
                    self.sock = None
                self.authenticated = False
                self.k_enc = None
                self.k_mac = None
                self.username = None
                self.root.after(0, lambda: self._build_login_screen(
                    "✅ Logged out successfully"))

        threading.Thread(target=_run, daemon=True).start()

    def on_close(self):
        """Clean shutdown."""
        if self.sock:
            try:
                if self.authenticated:
                    # try to send logout
                    timestamp = generate_timestamp()
                    request = pack_fields(b"LOGOUT", b"", timestamp)
                    encrypted = encrypt_and_mac(self.k_enc, self.k_mac, request)
                    send_data(self.sock, encrypted)
            except Exception:
                pass
            try:
                self.sock.close()
            except Exception:
                pass
        self.root.destroy()

    def run(self):
        """Start the Tkinter event loop."""
        self.root.mainloop()


# Main Entry Point
if __name__ == '__main__':
    print_separator("COE817 SECURE ATM CLIENT")
    print(f"  Connecting to bank server at {HOST}:{PORT}")
    print_separator()

    app = ATMClientGUI()
    app.run()
