import json
import os
import tkinter as tk
from tkinter import filedialog, messagebox
from cryptography.fernet import Fernet


# Load key with additional check for Fernet compatibility
def load_key_file(filepath):
    print(f"Loading key file from: {filepath}")
    try:
        with open(filepath, "r") as file:
            key = file.read().encode()
            # Check if key is compatible with Fernet
            fernet_test = Fernet(key)  # Will raise an error if invalid
        print("Key file loaded successfully:", key)
        return key
    except Exception as e:
        print(f"Error loading key file: {e}")
        messagebox.showerror("Invalid Key File", f"Error loading key file: {e}")
        return None


# Load obfuscated text with basic format check
def load_text_file(filepath):
    print(f"Loading obfuscated text file from: {filepath}")
    try:
        with open(filepath, "r") as file:
            text = file.read().strip()
        if not text.startswith("gAAAAAB"):  # Fernet encrypted text typically starts this way
            raise ValueError("Obfuscated text does not appear to be encrypted with Fernet.")
        print("Text file loaded successfully:", text[:50])  # Show preview
        return text
    except Exception as e:
        print(f"Error loading text file: {e}")
        messagebox.showerror("Invalid Text File", f"Error loading text file: {e}")
        return None


# Load map file with structure check
def load_map_file(filepath):
    print(f"Loading map file from: {filepath}")
    try:
        with open(filepath, "r") as file:
            map_data = json.load(file)
        if isinstance(map_data, dict):
            print("Map file loaded successfully:", map_data)
            return map_data
        else:
            raise ValueError("Map file should contain a dictionary.")
    except Exception as e:
        print(f"Error loading map file: {e}")
        messagebox.showerror("Invalid Map File", f"Error loading map file: {e}")
        return None


# Decryption with detailed error messages
def decrypt_and_deobfuscate(key, obfuscated_text, obfuscation_map):
    print("Starting decryption and deobfuscation process.")
    print("Using key:", key)
    print("Obfuscated text preview:", obfuscated_text[:50])  # Preview to confirm format
    try:
        fernet = Fernet(key)
        decrypted_text = fernet.decrypt(obfuscated_text.encode()).decode()
        print("Decryption successful.")

        # Deobfuscate by replacing obfuscated names with original names
        for obfuscated_name, original_name in obfuscation_map.items():
            decrypted_text = decrypted_text.replace(obfuscated_name, original_name)
        print("Deobfuscation complete.")

        # Save result to file
        filename = save_to_file(decrypted_text, "Obfuscated", "DeObfuscatedCode.txt")
        messagebox.showinfo("Decryption Completed", f"Deobfuscated code saved to: {filename}")
    except Exception as e:
        print(f"Decryption failed with error: {e}")
        messagebox.showerror("Decryption Error", f"Failed to decrypt: {e}")


# File save utility
def save_to_file(content, directory, filename):
    if not os.path.exists(directory):
        os.makedirs(directory)

    full_path = os.path.join(directory, filename)
    if os.path.exists(full_path):
        base, ext = os.path.splitext(filename)
        count = 1
        while os.path.exists(os.path.join(directory, f"{base}_{count}{ext}")):
            count += 1
        full_path = os.path.join(directory, f"{base}_{count}{ext}")

    with open(full_path, "w") as file:
        file.write(content)

    print(f"Decrypted code saved to: {full_path}")
    return full_path


# GUI setup
root = tk.Tk()
root.title("Smart Contract Deobfuscator")
root.geometry("500x400")

# Variables for file paths
key_file_path = tk.StringVar()
text_file_path = tk.StringVar()
map_file_path = tk.StringVar()


# Functions to select files
def select_key_file():
    filepath = filedialog.askopenfilename(filetypes=[("Text files", "*.txt")])
    if filepath:
        key_file_path.set(filepath)
        print(f"Selected key file: {filepath}")


def select_text_file():
    filepath = filedialog.askopenfilename(filetypes=[("Text files", "*.txt")])
    if filepath:
        text_file_path.set(filepath)
        print(f"Selected text file: {filepath}")


def select_map_file():
    filepath = filedialog.askopenfilename(filetypes=[("JSON files", "*.json")])
    if filepath:
        map_file_path.set(filepath)
        print(f"Selected map file: {filepath}")


# Start deobfuscation
def start_deobfuscation():
    if not (key_file_path.get() and text_file_path.get() and map_file_path.get()):
        messagebox.showerror("Missing File", "Please select all required files.")
        return

    # Load files with validation
    key = load_key_file(key_file_path.get())
    obfuscated_text = load_text_file(text_file_path.get())
    obfuscation_map = load_map_file(map_file_path.get())

    # If files loaded successfully, proceed with decryption
    if key and obfuscated_text and obfuscation_map:
        decrypt_and_deobfuscate(key, obfuscated_text, obfuscation_map)
    else:
        print("One or more files failed to load correctly.")


# GUI layout
tk.Label(root, text="Select the key file:").pack(pady=5)
tk.Entry(root, textvariable=key_file_path, width=60).pack(pady=5)
tk.Button(root, text="Browse", command=select_key_file).pack(pady=5)

tk.Label(root, text="Select the obfuscated code file:").pack(pady=5)
tk.Entry(root, textvariable=text_file_path, width=60).pack(pady=5)
tk.Button(root, text="Browse", command=select_text_file).pack(pady=5)

tk.Label(root, text="Select the obfuscation map file:").pack(pady=5)
tk.Entry(root, textvariable=map_file_path, width=60).pack(pady=5)
tk.Button(root, text="Browse", command=select_map_file).pack(pady=5)

tk.Button(root, text="Deobfuscate", command=start_deobfuscation).pack(pady=20)

root.mainloop()
