import tkinter as tk
from tkinter import *
from tkinter import ttk

def caesar_cipher(text, key):
    result = ""
    for char in text:
        if char.isalpha():
            # Determine whether the character is uppercase or lowercase
            is_upper = char.isupper()
            # Apply the Caesar cipher shift to the right
            shifted_char = chr((ord(char) - ord('A' if is_upper else 'a') + key) % 26 + ord('A' if is_upper else 'a'))
            result += shifted_char
        else:
            # If the character is not a letter, keep it unchanged
            result += char
    return result

def caesar_cipher_decrypt(ciphertext, key):
    result = ""
    for char in ciphertext:
        if char.isalpha():
            is_upper = char.isupper()
            # Apply the Caesar cipher shift to the left
            shifted_char = chr((ord(char) - ord('A' if is_upper else 'a') - key) % 26 + ord('A' if is_upper else 'a'))
            result += shifted_char
        else:
            result += char
    return result


def reverse_cipher(text):
    words = text.split()
    reversed_words = [word[::-1] for word in words]
    return ' '.join(reversed_words)

def combination_cipher(text, key):
    encrypted_text_caesar = caesar_cipher(text, key)
    encrypted_text_reverse = reverse_cipher(encrypted_text_caesar)
    return encrypted_text_reverse

def combination_cipher_decrypt(ciphertext, key):
    encrypted_text_reverse = reverse_cipher(ciphertext)
    encrypted_text_caesar = caesar_cipher_decrypt(encrypted_text_reverse, key)
    return encrypted_text_caesar


def encrypt():
    key = int(key_entry.get())
    plaintext = plaintext_text.get("1.0", tk.END).strip()
    key = key % 26
    iteration = key

    if iteration <= 10:
        iteration = 10

    for i in range(iteration):
        encrypted_text_combination = combination_cipher(plaintext, key)
        plaintext = encrypted_text_combination

    ciphertext_text.config(state="normal")
    ciphertext_text.delete("1.0", tk.END)
    ciphertext_text.insert(tk.END, plaintext)
    ciphertext_text.config(state="disabled")

def decrypt():
    key = int(key_entry2.get())
    ciphertext = ciphertext_box.get("1.0", tk.END).strip()
    key = key % 26
    iteration = key

    if iteration <= 10:
        iteration = 10

    for i in range(iteration):
        decrypted_text_combination = combination_cipher_decrypt(ciphertext, key)  
        ciphertext = decrypted_text_combination

    plaintext_box.config(state="normal")
    plaintext_box.delete("1.0", tk.END)
    plaintext_box.insert(tk.END, ciphertext)
    plaintext_box.config(state="disabled")

def is_number(char):
    try:
        int(char)
        return True
    except ValueError:
        return False

def validate_key(char):
    return is_number(char)

def clear_all():
    # Clear all input and output fields
    ciphertext_text.config(state="normal")
    plaintext_box.config(state="normal")
    ciphertext_box.delete("1.0", tk.END)
    plaintext_text.delete("1.0", tk.END)
    key_entry.delete(0, tk.END)
    key_entry2.delete(0, tk.END)
    ciphertext_text.delete("1.0", tk.END)
    ciphertext_text.config(state="disabled")
    plaintext_box.delete("1.0", tk.END)
    plaintext_box.config(state="disabled")


# Create the main window
root = tk.Tk()

encryption_page = Frame(root)
decryption_page = Frame(root)

encryption_page.grid(row=0, column=0, sticky="nsew")
decryption_page.grid(row=0, column=0, sticky="nsew")

#ENCRYPTION PAGE
title_label = ttk.Label(encryption_page, width=50, text="Combination of 2 Classic Cryptography", font=("Trajan Pro", 18))
title_label.pack(pady=20, padx=(83, 0))

plaintext_label = ttk.Label(encryption_page, width=50, text="Enter Plaintext:")
plaintext_label.pack(pady=1, padx=(10, 150))

plaintext_text = tk.Text(encryption_page, width=50, height=5)
plaintext_text.pack(pady=5, padx=(10, 150))

key_label = ttk.Label(encryption_page, width=50, text="Enter Key:")
key_label.pack(pady=2, padx=(10, 150))

validate_key_cmd = (encryption_page.register(validate_key), '%S')
key_entry = ttk.Spinbox(encryption_page, from_=0, to=100, width=30, validate="key", validatecommand=validate_key_cmd)
key_entry.pack(pady=5, padx=(10, 150))

encrypt_button = ttk.Button(encryption_page, text="Encrypt", command=encrypt)
encrypt_button.pack(pady=10, padx=(10, 150))

ciphertext_label = ttk.Label(encryption_page, width=50, text="Ciphertext:")
ciphertext_label.pack(pady=2, padx=(10, 150))

ciphertext_text = tk.Text(encryption_page, width=50, height=5, state="disabled")
ciphertext_text.pack(pady=5, padx=(10, 150))

clear_button = ttk.Button(encryption_page, text="Clear All", command=clear_all)
clear_button.pack(pady=10, padx=(10, 150))

nav_button = ttk.Button(encryption_page, text="Start Decrypting", command=lambda: decryption_page.tkraise())
nav_button.pack(pady=10, padx=(10, 150))



#DECRYPTION PAGE
title_label = ttk.Label(decryption_page, width=50, text="Combination of 2 Classic Cryptography", font=("Trajan Pro", 18))
title_label.pack(pady=20, padx=(83, 0))

label_ciphertext = ttk.Label(decryption_page, width=50, text="Enter Ciphertext:")
label_ciphertext.pack(pady=1, padx=(10, 150))

ciphertext_box = tk.Text(decryption_page, width=50, height=5)
ciphertext_box.pack(pady=5, padx=(10, 150))

key_label = ttk.Label(decryption_page, width=50, text="Enter Key:")
key_label.pack(pady=2, padx=(10, 150))

validate_key_cmd = (decryption_page.register(validate_key), '%S')
key_entry2 = ttk.Spinbox(decryption_page, from_=0, to=100, width=30, validate="key", validatecommand=validate_key_cmd)
key_entry2.pack(pady=5, padx=(10, 150))

decrypt_button = ttk.Button(decryption_page, text="Decrypt", command=decrypt)
decrypt_button.pack(pady=10, padx=(10, 150))

label_plaintext = ttk.Label(decryption_page, width=50, text="Plainrtext:")
label_plaintext.pack(pady=2, padx=(10, 150))

plaintext_box = tk.Text(decryption_page, width=50, height=5, state="disabled")
plaintext_box.pack(pady=5, padx=(10, 150))

clear_button = ttk.Button(decryption_page, text="Clear All", command=clear_all)
clear_button.pack(pady=10, padx=(10, 150))

nav_button2 = ttk.Button(decryption_page, text="Start Encrypting", command=lambda: encryption_page.tkraise())
nav_button2.pack(pady=10, padx=(10, 150))

encryption_page.tkraise()
root.title("Combined Cryptography")
root.geometry("600x500")
root.mainloop()
