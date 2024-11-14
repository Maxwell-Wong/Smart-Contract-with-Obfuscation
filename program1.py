from cryptography.fernet import Fernet
import random
import string
import os
import json
import tkinter as tk
from tkinter import scrolledtext
from tkinter import messagebox


# Function to generate a random key for encryption
def generate_key():
    return Fernet.generate_key()


# Function to encrypt a given value
def encrypt_value(value, key):
    fernet = Fernet(key)
    encrypted_value = fernet.encrypt(value.encode())
    return encrypted_value.decode()


# Function to obfuscate names (functions and variables)
def obfuscate_names(contract_code):
    obfuscation_map = {}
    obfuscated_code = contract_code

    # Detect functions and variables to obfuscate (basic keyword list for demonstration)
    keywords_to_obfuscate = ["value", "owner", "getValue", "setValue", "resetValue", "transferOwnership", "isOwner"]

    for name in keywords_to_obfuscate:
        obfuscated_name = ''.join(random.choices(string.ascii_letters, k=8))
        obfuscation_map[name] = obfuscated_name
        obfuscated_code = obfuscated_code.replace(name, obfuscated_name)

    return obfuscated_code, obfuscation_map


# Function to perform control flow obfuscation
def control_flow_obfuscation(contract_code):
    obfuscated_code = contract_code.replace("require(", "if (false) {")
    obfuscated_code = obfuscated_code.replace("else {", "if (true) {")
    return obfuscated_code


# Function to save content to specific directories with unique filenames
def save_to_file(content, directory, filename, binary=False):
    if not os.path.exists(directory):
        os.makedirs(directory)

    full_path = os.path.join(directory, filename)
    if os.path.exists(full_path):
        base, ext = os.path.splitext(filename)
        count = 1
        while os.path.exists(os.path.join(directory, f"{base}_{count}{ext}")):
            count += 1
        full_path = os.path.join(directory, f"{base}_{count}{ext}")

    with open(full_path, "wb" if binary else "w") as f:
        if isinstance(content, dict):  # For JSON files (obfuscation map)
            json.dump(content, f, indent=4)
        elif binary:
            f.write(content)
        else:
            f.write(content)

    return full_path


# GUI function to handle obfuscation and encryption
def obfuscate_and_encrypt_contract():
    contract_code = text_area.get("1.0", tk.END).strip()
    if not contract_code:
        messagebox.showerror("Error", "Please enter the contract code.")
        return

    # Generate encryption key and apply obfuscation techniques
    key = generate_key()
    obfuscated_code = control_flow_obfuscation(contract_code)
    obfuscated_code, obfuscation_map = obfuscate_names(obfuscated_code)

    # Encrypt the obfuscated code
    fernet = Fernet(key)
    encrypted_obfuscated_code = fernet.encrypt(obfuscated_code.encode())

    # Save obfuscated code, encryption key, and obfuscation map to respective directories
    obfuscated_filename = save_to_file(encrypted_obfuscated_code, "Obfuscated", "ObfuscatedCode.txt", binary=True)
    key_filename = save_to_file(key, "Key", "key.txt", binary=True)
    map_filename = save_to_file(obfuscation_map, "Map", "obfuscation_map.json")

    # Show a success message
    result = f"Obfuscated Contract Code saved to: {obfuscated_filename}\n" \
             f"Key saved to: {key_filename}\n" \
             f"Obfuscation Map saved to: {map_filename}\n\n" \
             f"Function & Variable Map: {obfuscation_map}\n" \
             f"Encryption Key (keep it safe): {key.decode()}"
    messagebox.showinfo("Obfuscation Completed", result)


# Setup GUI
root = tk.Tk()
root.title("Smart Contract Obfuscator")
root.geometry("800x600")

label = tk.Label(root, text="Enter the smart contract code:")
label.pack()

text_area = scrolledtext.ScrolledText(root, wrap=tk.WORD, width=90, height=25)
text_area.pack(pady=10)

obfuscate_button = tk.Button(root, text="Obfuscate & Encrypt", command=obfuscate_and_encrypt_contract)
obfuscate_button.pack(pady=20)

root.mainloop()
