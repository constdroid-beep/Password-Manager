import base64
import csv
import json
import os
import sys
import re
import secrets
import string
import logging
from collections import defaultdict
from datetime import datetime
import threading
import time

import tkinter as tk
from tkinter import simpledialog, messagebox
from tkinter import scrolledtext

from cryptography.hazmat.primitives.kdf.argon2 import Argon2id
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes, hmac
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('password_manager.log'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

# Security Constants
PBKDF2_ITERATIONS = 600000
ARGON2_MEMORY = 65540
ARGON2_TIME = 3
ARGON2_PARALLELISM = 4
SALT_LENGTH = 32
IV_LENGTH = 16
TAG_LENGTH = 16
SESSION_TIMEOUT = 15 * 60
MAX_LOGIN_ATTEMPTS = 5
LOCKOUT_DURATION = 300
PASSWORD_MIN_LENGTH = 8

# File format version
DATA_FORMAT_VERSION = "2.0"

# Global variables
passwords = []
salt_file = "salt.bin"
master_salt_file = "master_salt.bin"
data_file = "passwords.enc"
legacy_data_file = "daten_encrypted.csv"
master_password_hash = None
session_start_time = None
encryption_key = None
metadata = {
    "version": DATA_FORMAT_VERSION,
    "created_at": None,
    "modified_at": None,
    "password_count": 0
}
failed_login_attempts = defaultdict(lambda: {"count": 0, "timestamp": None})

def check_login_attempts(client_id="default"):
    """Check if account is locked due to failed login attempts"""
    attempt_info = failed_login_attempts[client_id]

    if attempt_info["count"] >= MAX_LOGIN_ATTEMPTS:
        if attempt_info["timestamp"]:
            time_diff = time.time() - attempt_info["timestamp"]
            if time_diff < LOCKOUT_DURATION:
                remaining = int(LOCKOUT_DURATION - time_diff)
                logger.warning(f"Account locked for {client_id}. Try again in {remaining}s")
                return False, remaining
            else:
                failed_login_attempts[client_id] = {"count": 0, "timestamp": None}
    return True, 0

def record_failed_login(client_id="default"):
    """Record a failed login attempt"""
    failed_login_attempts[client_id]["count"] += 1
    failed_login_attempts[client_id]["timestamp"] = time.time()
    logger.warning(f"Failed login attempt for {client_id}. Count: {failed_login_attempts[client_id]['count']}")

def reset_login_attempts(client_id="default"):
    """Reset failed login attempts after successful login"""
    failed_login_attempts[client_id] = {"count": 0, "timestamp": None}

def key_from_master_argon2(master_password):
    """Derive encryption key from master password using Argon2id"""
    if os.path.exists(salt_file):
        with open(salt_file, "rb") as f:
            salt = f.read()
    else:
        salt = secrets.token_bytes(SALT_LENGTH)
        _save_salt(salt, salt_file)

    kdf = Argon2id(
        salt=salt,
        length=32,
        iterations=ARGON2_TIME,
        lanes=ARGON2_PARALLELISM,
        memory_cost=ARGON2_MEMORY
    )
    key = base64.urlsafe_b64encode(kdf.derive(master_password.encode()))
    return key, salt

def hash_master_password_secure(master_password):
    """
    Hash master password using Argon2id with separate salt
    This is used for verification, not encryption
    """
    if os.path.exists(master_salt_file):
        with open(master_salt_file, "rb") as f:
            salt = f.read()
    else:
        salt = secrets.token_bytes(SALT_LENGTH)
        _save_salt(salt, master_salt_file)

    kdf = Argon2id(
        salt=salt,
        length=32,
        iterations=ARGON2_TIME,
        lanes=ARGON2_PARALLELISM,
        memory_cost=ARGON2_MEMORY
    )
    return kdf.derive(master_password.encode())

def _save_salt(salt, filename):
    """Save salt to file"""
    with open(filename, "wb") as f:
        f.write(salt)
    logger.info(f"Salt securely stored in {filename}")

def compute_hmac(data, key):
    """Compute HMAC-SHA256 for data integrity"""
    h = hmac.HMAC(base64.urlsafe_b64decode(key), hashes.SHA256())
    h.update(data)
    return h.finalize()

def verify_hmac(data, mac, key):
    """Verify HMAC-SHA256 for data integrity"""
    h = hmac.HMAC(base64.urlsafe_b64decode(key), hashes.SHA256())
    h.update(data)
    try:
        h.verify(mac)
        return True
    except Exception:
        return False

def encrypt_data(plaintext, key):
    """Encrypt data using AES-256-GCM with HMAC for additional integrity"""
    iv = secrets.token_bytes(IV_LENGTH)
    cipher = Cipher(
        algorithms.AES(base64.urlsafe_b64decode(key)),
        modes.GCM(iv),
        backend=default_backend()
    )
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(plaintext) + encryptor.finalize()

    # Combine: IV + GCM_TAG + CIPHERTEXT
    encrypted_data = iv + encryptor.tag + ciphertext

    # Add HMAC for additional integrity check
    mac = compute_hmac(encrypted_data, key)

    return mac + encrypted_data

def decrypt_data(encrypted_data, key):
    """Decrypt data using AES-256-GCM and verify HMAC"""
    # Extract HMAC (first 32 bytes)
    mac = encrypted_data[:32]
    encrypted_data = encrypted_data[32:]

    # Verify HMAC first
    if not verify_hmac(encrypted_data, mac, key):
        raise ValueError("HMAC verification failed - data may be corrupted or tampered")

    key_bytes = base64.urlsafe_b64decode(key)
    iv = encrypted_data[:IV_LENGTH]
    tag = encrypted_data[IV_LENGTH:IV_LENGTH + TAG_LENGTH]
    ciphertext = encrypted_data[IV_LENGTH + TAG_LENGTH:]

    cipher = Cipher(
        algorithms.AES(key_bytes),
        modes.GCM(iv, tag),
        backend=default_backend()
    )
    decryptor = cipher.decryptor()
    plaintext = decryptor.update(ciphertext) + decryptor.finalize()
    return plaintext

def decrypt_data_legacy(encrypted_data, key):
    """Decrypt old CSV format data (without HMAC) for backward compatibility"""
    key_bytes = base64.urlsafe_b64decode(key)
    iv = encrypted_data[:IV_LENGTH]
    tag = encrypted_data[IV_LENGTH:IV_LENGTH + TAG_LENGTH]
    ciphertext = encrypted_data[IV_LENGTH + TAG_LENGTH:]

    cipher = Cipher(
        algorithms.AES(key_bytes),
        modes.GCM(iv, tag),
        backend=default_backend()
    )
    decryptor = cipher.decryptor()
    plaintext = decryptor.update(ciphertext) + decryptor.finalize()
    return plaintext

def check_session_timeout():
    """Check if session has timed out"""
    global session_start_time
    if session_start_time is None:
        return False

    elapsed = time.time() - session_start_time
    if elapsed > SESSION_TIMEOUT:
        messagebox.showwarning("Session Timeout", "Your session has expired. Please restart.")
        logger.warning("Session timeout occurred")
        sys.exit(1)
    return True

def reset_session_timeout():
    """Reset session timeout on user activity"""
    global session_start_time
    session_start_time = time.time()

def clear_session_data():
    """Clear sensitive session data (best effort in Python)"""
    global encryption_key, master_password_hash
    encryption_key = None
    master_password_hash = None
    logger.info("Session data cleared")

def migrate_from_legacy():
    """Migrate from old CSV format to new JSON format"""
    global passwords, metadata, encryption_key

    if not os.path.exists(legacy_data_file) or os.path.exists(data_file):
        return False

    try:
        logger.info("Detected legacy CSV format - starting migration...")

        with open(legacy_data_file, "rb") as f:
            encrypted = f.read()

        # Try to decrypt with legacy method (no HMAC)
        decrypted = decrypt_data_legacy(encrypted, encryption_key)
        plaintext = decrypted.decode("utf-8")

        # Parse CSV
        reader = csv.DictReader(plaintext.splitlines())
        passwords = list(reader)

        # Update metadata
        metadata["created_at"] = datetime.now().isoformat()
        metadata["modified_at"] = datetime.now().isoformat()
        metadata["password_count"] = len(passwords)

        # Save in new format
        speichere_passwoerter()

        # Backup old file
        backup_name = legacy_data_file + ".backup"
        os.rename(legacy_data_file, backup_name)

        logger.info(f"Migration successful! {len(passwords)} passwords migrated. Old file backed up as {backup_name}")
        messagebox.showinfo("Migration", f"Successfully migrated {len(passwords)} passwords to new format!\n\nOld file backed up.")

        return True

    except Exception as e:
        logger.error(f"Migration failed: {str(e)}")
        return False

def lade_passwoerter(master_password):
    """Load and decrypt passwords from file"""
    global passwords, master_password_hash, session_start_time, encryption_key, metadata

    can_login, lockout_time = check_login_attempts()
    if not can_login:
        messagebox.showerror("Account Locked", f"Too many failed attempts. Wait {lockout_time}s and try again.")
        sys.exit(1)

    passwords = []

    # Derive key first
    key, _ = key_from_master_argon2(master_password)
    encryption_key = key

    # First time setup
    if not os.path.exists(data_file) and not os.path.exists(legacy_data_file):
        master_password_hash = hash_master_password_secure(master_password)
        session_start_time = time.time()
        metadata["created_at"] = datetime.now().isoformat()
        metadata["modified_at"] = datetime.now().isoformat()
        metadata["password_count"] = 0
        reset_login_attempts()
        logger.info("New password manager initialized with JSON format")
        return True

    # Check for legacy migration
    if os.path.exists(legacy_data_file) and not os.path.exists(data_file):
        master_password_hash = hash_master_password_secure(master_password)
        session_start_time = time.time()
        reset_login_attempts()
        migrate_from_legacy()
        return True

    # Load new JSON format
    try:
        with open(data_file, "rb") as f:
            encrypted = f.read()

        decrypted = decrypt_data(encrypted, key)
        data = json.loads(decrypted.decode("utf-8"))

        # Validate version
        if "version" not in data:
            raise ValueError("Invalid data format - missing version")

        # Extract metadata and passwords
        metadata.update({
            "version": data.get("version", DATA_FORMAT_VERSION),
            "created_at": data.get("created_at"),
            "modified_at": data.get("modified_at"),
            "password_count": data.get("password_count", 0)
        })

        passwords = data.get("passwords", [])

        # Success - store hash
        master_password_hash = hash_master_password_secure(master_password)
        session_start_time = time.time()
        reset_login_attempts()

        logger.info(f"Successfully loaded {len(passwords)} passwords (Format v{metadata['version']})")
        return True

    except Exception as e:
        record_failed_login()
        logger.error(f"Authentication failed: {str(e)}")
        messagebox.showerror("Error", "Wrong master password or corrupted data")
        return False

def speichere_passwoerter():
    """Save and encrypt passwords to file in JSON format"""
    global passwords, encryption_key, metadata

    if encryption_key is None:
        logger.error("No encryption key available")
        messagebox.showerror("Error", "No encryption key available")
        return False

    try:
        # Update metadata
        metadata["modified_at"] = datetime.now().isoformat()
        metadata["password_count"] = len(passwords)
        metadata["version"] = DATA_FORMAT_VERSION

        if metadata["created_at"] is None:
            metadata["created_at"] = datetime.now().isoformat()

        # Create JSON structure
        data = {
            "version": metadata["version"],
            "created_at": metadata["created_at"],
            "modified_at": metadata["modified_at"],
            "password_count": metadata["password_count"],
            "passwords": passwords
        }

        # Serialize to JSON
        plaintext = json.dumps(data, indent=2).encode("utf-8")

        # Encrypt
        encrypted = encrypt_data(plaintext, encryption_key)

        # Save to file
        with open(data_file, "wb") as f:
            f.write(encrypted)

        logger.info(f"Securely saved {len(passwords)} passwords in JSON format v{metadata['version']}")
        return True

    except Exception as e:
        logger.error(f"Failed to save passwords: {str(e)}")
        messagebox.showerror("Error", f"Failed to save passwords: {str(e)}")
        return False

def create(length=16):
    """Generate a cryptographically secure random password"""
    if length < PASSWORD_MIN_LENGTH:
        length = PASSWORD_MIN_LENGTH

    # Ensure at least one of each character type
    password_chars = [
        secrets.choice(string.ascii_uppercase),
        secrets.choice(string.ascii_lowercase),
        secrets.choice(string.digits),
        secrets.choice("@$!%*?&#^-_+=")
    ]

    all_chars = string.ascii_letters + string.digits + "@$!%*?&#^-_+="
    password_chars += [secrets.choice(all_chars) for _ in range(length - 4)]

    # Shuffle using secrets
    chars_list = list(password_chars)
    for i in range(len(chars_list) - 1, 0, -1):
        j = secrets.randbelow(i + 1)
        chars_list[i], chars_list[j] = chars_list[j], chars_list[i]

    return ''.join(chars_list)

def createown(name, passwort):
    """Create and store a custom password"""
    if not check_session_timeout():
        return

    reset_session_timeout()

    if not name or not passwort:
        messagebox.showerror("Error", "Name and password cannot be empty")
        return

    if any(p["name"].lower() == name.lower() for p in passwords):
        messagebox.showerror("Error", f"Password for '{name}' already exists")
        return

    strength = starkes_passwort(passwort)

    if strength != "Strong password":
        confirm = messagebox.askyesno(
            "Weak Password",
            f"Password strength: {strength}\n\nContinue anyway?"
        )
        if not confirm:
            return

    passwords.append({"password": passwort, "name": name})
    logger.info(f"Password added for: {name}")
    messagebox.showinfo("Saved", f"Password for '{name}' saved securely!")

def Viewer():
    """View all stored passwords in a temporary window"""
    if not check_session_timeout():
        return

    reset_session_timeout()

    if not passwords:
        messagebox.showinfo("Info", "No passwords stored")
        return

    viewer_window = tk.Toplevel()
    viewer_window.title("Password Viewer (Auto-closes in 30s)")
    viewer_window.geometry("600x400")

    text_widget = scrolledtext.ScrolledText(viewer_window, wrap=tk.WORD, state=tk.NORMAL)
    text_widget.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)

    output = "\n".join([f"[{i+1}] {p['name']}: {p['password']}" for i, p in enumerate(passwords)])
    text_widget.insert(tk.END, output)
    text_widget.config(state=tk.DISABLED)

    def auto_close():
        time.sleep(30)
        try:
            viewer_window.destroy()
        except:
            pass

    threading.Thread(target=auto_close, daemon=True).start()

    def on_close():
        try:
            viewer_window.clipboard_clear()
        except:
            pass
        viewer_window.destroy()

    viewer_window.protocol("WM_DELETE_WINDOW", on_close)
    logger.info("Password viewer opened")

def changer():
    """Change an existing password"""
    if not check_session_timeout():
        return

    reset_session_timeout()

    if not passwords:
        messagebox.showinfo("Info", "No passwords to change")
        return

    names = [p["name"] for p in passwords]
    name = simpledialog.askstring("Change Password", f"Which password?\n\nOptions:\n{chr(10).join(names)}")

    if not name:
        return

    for p in passwords:
        if p["name"].lower() == name.lower():
            new_pw = simpledialog.askstring("New Password", "Enter new password:", show="*")
            if not new_pw:
                return

            strength = starkes_passwort(new_pw)
            if strength != "Strong password":
                confirm = messagebox.askyesno(
                    "Weak Password",
                    f"Password strength: {strength}\n\nContinue anyway?"
                )
                if not confirm:
                    return

            p["password"] = new_pw
            logger.info(f"Password changed for: {name}")
            messagebox.showinfo("Changed", "Password changed securely!")
            return

    messagebox.showerror("Error", "Name not found")

def delete_all_passwords():
    """Delete all stored passwords after confirmation"""
    if not check_session_timeout():
        return

    reset_session_timeout()

    # First warning
    if not messagebox.askyesno("Confirm Deletion", "This will DELETE ALL passwords permanently!\n\nAre you sure?"):
        return

    # Second confirmation
    if not messagebox.askyesno("Final Confirmation", "Are you REALLY SURE?\n\nThis cannot be undone!"):
        return

    # Clear passwords
    passwords.clear()
    logger.warning("All passwords deleted by user")
    messagebox.showinfo("Deleted", "All passwords have been deleted")

def starkes_passwort(pw):
    """Check password strength"""
    if len(pw) < PASSWORD_MIN_LENGTH:
        return f"Too short (min {PASSWORD_MIN_LENGTH} chars)"
    if not re.search(r"[A-Z]", pw):
        return "Missing uppercase letter"
    if not re.search(r"[a-z]", pw):
        return "Missing lowercase letter"
    if not re.search(r"\d", pw):
        return "Missing number"
    if not re.search(r"[@$!%*?&#^-_+=]", pw):
        return "Missing special character"

    # Basic entropy check
    entropy = len(pw) * 6.6
    if entropy < 50:
        return "Weak (low entropy)"

    return "Strong password"

def main_gui():
    """Main GUI application"""
    root = tk.Tk()
    root.withdraw()

    # Master password authentication
    max_retries = 3
    for attempt in range(max_retries):
        master_password = simpledialog.askstring(
            "Master Password",
            "Enter master password:",
            show="*"
        )

        if not master_password:
            sys.exit(0)

        if lade_passwoerter(master_password):
            break
        else:
            remaining = max_retries - attempt - 1
            if remaining > 0:
                messagebox.showerror("Error", f"Authentication failed. {remaining} attempts remaining.")
            else:
                sys.exit(1)

    # Show main window
    root.deiconify()
    root.title("🔐 Secure Password Manager v2.0")
    root.geometry("500x580")
    root.resizable(False, False)

    title_label = tk.Label(root, text="🔐 Secure Password Manager", font=("Arial", 14, "bold"))
    title_label.pack(pady=10)

    status_label = tk.Label(root, text="Session active - 15 min timeout", fg="green", font=("Arial", 9))
    status_label.pack()

    # Info label with metadata
    info_text = f"Passwords: {len(passwords)}"
    if metadata.get("created_at"):
        created = datetime.fromisoformat(metadata["created_at"]).strftime("%Y-%m-%d")
        info_text += f" | Created: {created}"

    metadata_label = tk.Label(root, text=info_text, fg="gray", font=("Arial", 8))
    metadata_label.pack()

    def update_status():
        """Update session timeout status"""
        if session_start_time:
            elapsed = int(time.time() - session_start_time)
            remaining = max(0, SESSION_TIMEOUT - elapsed)
            status_label.config(text=f"Session: {remaining}s remaining")
        root.after(1000, update_status)

    update_status()

    button_frame = tk.Frame(root)
    button_frame.pack(pady=20, fill=tk.BOTH, padx=20)

    tk.Button(
        button_frame,
        text="🔐 Generate Strong Password",
        command=lambda: createown(
            simpledialog.askstring("Name", "Enter name:"),
            create()
        ),
        bg="#4CAF50",
        fg="white",
        font=("Arial", 10),
        padx=10,
        pady=8
    ).pack(fill=tk.X, pady=5)

    tk.Button(
        button_frame,
        text="✏️ Create Own Password",
        command=lambda: createown(
            simpledialog.askstring("Name", "Enter name:"),
            simpledialog.askstring("Password", "Enter password:", show="*")
        ),
        bg="#2196F3",
        fg="white",
        font=("Arial", 10),
        padx=10,
        pady=8
    ).pack(fill=tk.X, pady=5)

    tk.Button(
        button_frame,
        text="👁️ View Passwords",
        command=Viewer,
        bg="#FF9800",
        fg="white",
        font=("Arial", 10),
        padx=10,
        pady=8
    ).pack(fill=tk.X, pady=5)

    tk.Button(
        button_frame,
        text="🔄 Change Password",
        command=changer,
        bg="#9C27B0",
        fg="white",
        font=("Arial", 10),
        padx=10,
        pady=8
    ).pack(fill=tk.X, pady=5)

    tk.Button(
        button_frame,
        text="🗑️ Delete All Passwords",
        command=delete_all_passwords,
        bg="#F44336",
        fg="white",
        font=("Arial", 10),
        padx=10,
        pady=8
    ).pack(fill=tk.X, pady=5)

    tk.Button(
        button_frame,
        text="💾 Save & Exit",
        command=lambda: (
            speichere_passwoerter(),
            clear_session_data(),
            logger.info("Application closed securely"),
            root.destroy(),
            sys.exit(0)
        ),
        bg="#607D8B",
        fg="white",
        font=("Arial", 10, "bold"),
        padx=10,
        pady=10
    ).pack(fill=tk.X, pady=5)

    security_info = tk.Label(
        root,
        text="✓ Argon2id KDF (Master + Data)\n✓ AES-256-GCM + HMAC-SHA256\n✓ JSON Format with Versioning\n✓ Secure Random (secrets)\n✓ Rate Limiting + Session Timeout\n✓ Integrity Verification",
        font=("Arial", 8),
        fg="gray",
        justify=tk.LEFT
    )
    security_info.pack(pady=10)

    root.mainloop()

if __name__ == "__main__":
    try:
        main_gui()
    except KeyboardInterrupt:
        clear_session_data()
        logger.info("Application interrupted by user")
        sys.exit(0)
    except Exception as e:
        logger.error(f"Unexpected error: {str(e)}")
        messagebox.showerror("Error", "An unexpected error occurred")
        sys.exit(1)
