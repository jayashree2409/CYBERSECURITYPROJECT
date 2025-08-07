pip install pycryptodome
from Crypto.Cipher import AES
from Crypto.Hash import SHA256
from Crypto.Random import get_random_bytes
import tkinter as tk
from tkinter import filedialog, messagebox
import os

# --- AES Utilities ---
def get_key(password):
    """Generate SHA-256 key from password"""
    hasher = SHA256.new(password.encode('utf-8'))
    return hasher.digest()  # 32 bytes = 256 bits

def encrypt_file(file_path, password):
    key = get_key(password)
    cipher = AES.new(key, AES.MODE_EAX)
    with open(file_path, 'rb') as f:
        plaintext = f.read()
    ciphertext, tag = cipher.encrypt_and_digest(plaintext)
    
    output_file = file_path + ".enc"
    with open(output_file, 'wb') as f:
        f.write(cipher.nonce)
        f.write(tag)
        f.write(ciphertext)
    return output_file

def decrypt_file(file_path, password):
    key = get_key(password)
    with open(file_path, 'rb') as f:
        nonce = f.read(16)
        tag = f.read(16)
        ciphertext = f.read()
    cipher = AES.new(key, AES.MODE_EAX, nonce)
    try:
        plaintext = cipher.decrypt_and_verify(ciphertext, tag)
    except ValueError:
        raise Exception("Wrong password or corrupted file!")

    output_file = file_path.replace(".enc", ".dec")
    with open(output_file, 'wb') as f:
        f.write(plaintext)
    return output_file

# --- GUI Functions ---
def select_file(mode):
    file_path = filedialog.askopenfilename()
    if not file_path:
        return
    password = password_entry.get()
    if not password:
        messagebox.showerror("Error", "Please enter a password")
        return
    
    try:
        if mode == "encrypt":
            out = encrypt_file(file_path, password)
            messagebox.showinfo("Success", f"File encrypted:\n{out}")
        elif mode == "decrypt":
            out = decrypt_file(file_path, password)
            messagebox.showinfo("Success", f"File decrypted:\n{out}")
    except Exception as e:
        messagebox.showerror("Error", str(e))
# --- GUI Interface ---
root = tk.Tk()
root.title("🔐 AES-256 File Encryption Tool")
root.geometry("400x200")
root.resizable(False, False)

tk.Label(root, text="Enter Password:", font=('Arial', 12)).pack(pady=10)
password_entry = tk.Entry(root, show="*", width=40)
password_entry.pack(pady=5)

tk.Button(root, text="🔒 Encrypt File", command=lambda: select_file("encrypt"), width=30, bg="#d1e7dd").pack(pady=10)
tk.Button(root, text="🔓 Decrypt File", command=lambda: select_file("decrypt"), width=30, bg="#f8d7da").pack(pady=5)

root.mainloop()
