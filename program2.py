from cryptography.fernet import Fernet
import random
import string
import os
import json
import tkinter as tk
from tkinter import scrolledtext, messagebox, filedialog
import re
from typing import Tuple, Dict, Any
import hashlib
import base64
from datetime import datetime


class ContractObfuscator:
    def __init__(self):
        self.salt = os.urandom(16)
        # Enhanced patterns to catch more variables and functions
        self.common_patterns = {
            r'\bfunction\s+(\w+)': 'function',
            r'\bcontract\s+(\w+)': 'contract',
            r'\bevent\s+(\w+)': 'event',
            r'\bmodifier\s+(\w+)': 'modifier',
            r'\buint256\s+(?:private|public|internal)?\s*(\w+)': 'uint_var',
            r'\baddress\s+(?:private|public|internal)?\s*(\w+)': 'address_var',
            r'\bbool\s+(?:private|public|internal)?\s*(\w+)': 'bool_var',
            r'\bstring\s+(?:private|public|internal)?\s*(\w+)': 'string_var',
            r'\bmapping\s*$$.*$$\s*(?:private|public|internal)?\s*(\w+)': 'mapping_var',
            r'\b(\w+)\s*$$[^)]*$$\s*{': 'function_call',
        }


    def generate_secure_key(self) -> bytes:
        """Generate a more secure key using additional entropy"""
        random_data = os.urandom(32) + str(random.randint(0, 1000000)).encode()
        key = hashlib.sha256(random_data + self.salt).digest()
        return base64.urlsafe_b64encode(key[:32])

    def encrypt_value(self, value: str, key: bytes) -> str:
        """Encrypt a value with error handling"""
        try:
            fernet = Fernet(key)
            encrypted_value = fernet.encrypt(value.encode())
            return encrypted_value.decode()
        except Exception as e:
            raise ValueError(f"Encryption failed: {str(e)}")

    def decrypt_value(self, encrypted_value: str, key: bytes) -> str:
        """Decrypt a value with error handling"""
        try:
            fernet = Fernet(key)
            decrypted_value = fernet.decrypt(encrypted_value.encode())
            return decrypted_value.decode()
        except Exception as e:
            raise ValueError(f"Decryption failed: {str(e)}")

    def generate_obfuscated_name(self, length: int = 16) -> str:
        """Generate more complex obfuscated names"""
        charset = string.ascii_letters + string.digits + '_$'
        return '_' + ''.join(random.choices(charset, k=length))

    def identify_smart_contract_elements(self, code: str) -> set:
        """Identify smart contract elements using regex patterns"""
        elements = set()
        for pattern in self.common_patterns.keys():
            matches = re.finditer(pattern, code)
            elements.update(match.group(1) for match in matches if match.group(1))
        return elements

    def generate_opaque_predicate(self) -> str:
        """Generate mathematically complex but always true/false conditions"""
        predicates = [
            f"(x * x - {random.randint(1, 100)} * x + {random.randint(1, 100)}) % 2 == 0",
            f"(x & (x - 1)) == 0",
            f"(x | {random.randint(1, 100)}) >= x",
            f"(x ^ (x >> 1)) != 0",
        ]
        return random.choice(predicates)

    def generate_dead_code(self) -> str:
        """Generate dead code that won't affect the contract's functionality"""
        dead_code_templates = [
            """
            function {func_name}() private pure {{
                uint256 x = {num1};
                if ({predicate}) {{
                    x = {num2};
                }}
                assembly {{
                    // Some assembly operations that don't affect state
                    let y := mul(x, {num3})
                    y := add(y, {num4})
                }}
            }}
            """,
            """
            function {func_name}() private view returns (bool) {{
                uint256 x = block.timestamp % {num1};
                return x > 0 && {predicate};
            }}
            """,
        ]

        template = random.choice(dead_code_templates)
        return template.format(
            func_name=self.generate_obfuscated_name(8),
            num1=random.randint(1, 1000),
            num2=random.randint(1, 1000),
            num3=random.randint(1, 1000),
            num4=random.randint(1, 1000),
            predicate=self.generate_opaque_predicate()
        )

    def insert_opaque_predicates(self, code: str) -> str:
        """Insert opaque predicates into the code"""
        # Find function bodies
        function_pattern = r'(function\s+\w+\s*$$[^)]*$$\s*{[^}]*})'
        functions = re.finditer(function_pattern, code)

        modified_code = code
        for match in functions:
            function_body = match.group(1)
            # Insert opaque predicate
            predicate = self.generate_opaque_predicate()
            modified_function = function_body.replace(
                '{',
                f'{{\n        uint256 x = uint256(block.timestamp);\n        require({predicate}, "Invalid state");\n',
                1
            )
            modified_code = modified_code.replace(function_body, modified_function)

        return modified_code

    def obfuscate_names(self, contract_code: str) -> Tuple[str, Dict[str, str]]:
        """Enhanced name obfuscation with better variable detection"""
        obfuscation_map = {}
        obfuscated_code = contract_code

        # First pass: identify all elements to obfuscate
        for pattern, _ in self.common_patterns.items():
            matches = re.finditer(pattern, contract_code)
            for match in matches:
                original_name = match.group(1)
                if original_name not in obfuscation_map and not original_name.startswith('_'):
                    obfuscated_name = self.generate_obfuscated_name()
                    while obfuscated_name in obfuscation_map.values():
                        obfuscated_name = self.generate_obfuscated_name()
                    obfuscation_map[original_name] = obfuscated_name

        # Sort by length (longest first) to prevent partial replacements
        sorted_elements = sorted(obfuscation_map.items(), key=lambda x: len(x[0]), reverse=True)

        # Second pass: replace all occurrences
        for original, obfuscated in sorted_elements:
            pattern = r'\b' + re.escape(original) + r'\b'
            obfuscated_code = re.sub(pattern, obfuscated, obfuscated_code)

        return obfuscated_code, obfuscation_map

    def control_flow_obfuscation(self, contract_code: str) -> str:
        """Enhanced control flow obfuscation with dead code and opaque predicates"""
        # First, add opaque predicates
        obfuscated_code = self.insert_opaque_predicates(contract_code)

        # Add dead code before the final closing brace
        dead_code_count = random.randint(3, 7)
        dead_code = '\n'.join(self.generate_dead_code() for _ in range(dead_code_count))

        # Insert dead code before the last closing brace
        if obfuscated_code.rstrip().endswith('}'):
            obfuscated_code = obfuscated_code.rstrip()[:-1] + '\n' + dead_code + '\n}'

        return obfuscated_code


class ObfuscatorGUI:
    def __init__(self):
        self.obfuscator = ContractObfuscator()
        self.setup_gui()

    def setup_gui(self):
        self.root = tk.Tk()
        self.root.title("Smart Contract Obfuscator/Deobfuscator")
        self.root.geometry("800x600")

        # Add menu bar
        self.create_menu()

        # Main content
        self.create_main_content()

    def create_menu(self):
        menubar = tk.Menu(self.root)
        file_menu = tk.Menu(menubar, tearoff=0)
        file_menu.add_command(label="Open", command=self.load_file)
        file_menu.add_command(label="Save", command=self.save_file)
        file_menu.add_separator()
        file_menu.add_command(label="Exit", command=self.root.quit)
        menubar.add_cascade(label="File", menu=file_menu)
        self.root.config(menu=menubar)

    def create_main_content(self):
        # Input area
        input_frame = tk.LabelFrame(self.root, text="Input Contract Code")
        input_frame.pack(fill="both", expand=True, padx=10, pady=5)

        self.text_area = scrolledtext.ScrolledText(
            input_frame, wrap=tk.WORD, width=90, height=25)
        self.text_area.pack(padx=5, pady=5)

        # Buttons frame
        button_frame = tk.Frame(self.root)
        button_frame.pack(fill="x", padx=10, pady=5)

        # Obfuscate button
        tk.Button(button_frame, text="Obfuscate",
                  command=self.obfuscate_contract).pack(side="left", padx=5)

        # Deobfuscate button
        tk.Button(button_frame, text="Deobfuscate",
                  command=self.deobfuscate_contract).pack(side="left", padx=5)

        # Clear button
        tk.Button(button_frame, text="Clear",
                  command=self.clear_text).pack(side="left", padx=5)

    def load_file(self):
        file_path = filedialog.askopenfilename(
            filetypes=[("Solidity files", "*.sol"), ("All files", "*.*")])
        if file_path:
            try:
                with open(file_path, 'r') as file:
                    self.text_area.delete(1.0, tk.END)
                    self.text_area.insert(tk.END, file.read())
            except Exception as e:
                messagebox.showerror("Error", f"Failed to load file: {str(e)}")

    def save_file(self):
        file_path = filedialog.asksaveasfilename(
            defaultextension=".sol",
            filetypes=[("Solidity files", "*.sol"), ("All files", "*.*")])
        if file_path:
            try:
                with open(file_path, 'w') as file:
                    file.write(self.text_area.get(1.0, tk.END))
            except Exception as e:
                messagebox.showerror("Error", f"Failed to save file: {str(e)}")

    def clear_text(self):
        self.text_area.delete(1.0, tk.END)

    def obfuscate_contract(self):
        try:
            contract_code = self.text_area.get("1.0", tk.END).strip()
            if not contract_code:
                raise ValueError("Please enter the contract code.")

            key = self.obfuscator.generate_secure_key()
            obfuscated_code = self.obfuscator.control_flow_obfuscation(contract_code)
            obfuscated_code, obfuscation_map = self.obfuscator.obfuscate_names(obfuscated_code)

            # Save files
            self.save_obfuscation_results(obfuscated_code, key, obfuscation_map)

        except Exception as e:
            messagebox.showerror("Error", str(e))

    def deobfuscate_contract(self):
        try:
            # Ask for the obfuscation map file
            map_path = filedialog.askopenfilename(
                title="Select obfuscation map file",
                filetypes=[("JSON files", "*.json")]
            )

            if not map_path:
                return

            # Load the obfuscation map
            with open(map_path, 'r') as f:
                obfuscation_map = json.load(f)

            # Get the obfuscated code from the text area
            obfuscated_code = self.text_area.get("1.0", tk.END).strip()

            # Remove dead code functions (identified by obfuscated names)
            code_lines = obfuscated_code.split('\n')
            cleaned_lines = []
            skip_function = False

            for line in code_lines:
                # Check if line contains a dead code function
                if any(obfuscated in line for obfuscated in obfuscation_map.values()):
                    if 'function' in line and '{' in line and '}' in line:
                        continue
                    elif 'function' in line and '{' in line:
                        skip_function = True
                        continue

                if skip_function:
                    if '}' in line:
                        skip_function = False
                    continue

                cleaned_lines.append(line)

            deobfuscated_code = '\n'.join(cleaned_lines)

            # Reverse the name obfuscation
            for original, obfuscated in obfuscation_map.items():
                deobfuscated_code = deobfuscated_code.replace(obfuscated, original)

            # Remove opaque predicates
            deobfuscated_code = re.sub(
                r'uint256 x = uint256$$block\.timestamp$$;[\s\n]*require$$[^;]+;',
                '',
                deobfuscated_code
            )

            # Clean up any remaining artifacts
            deobfuscated_code = re.sub(r'\n\s*\n\s*\n', '\n\n', deobfuscated_code)

            # Clear the text area and insert the deobfuscated code
            self.text_area.delete(1.0, tk.END)
            self.text_area.insert(tk.END, deobfuscated_code)

            messagebox.showinfo("Success", "Contract has been deobfuscated successfully!")

        except Exception as e:
            messagebox.showerror("Error", f"Deobfuscation failed: {str(e)}")

    def save_obfuscation_results(self, obfuscated_code, key, obfuscation_map):
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")

        # Create directories if they don't exist
        for dir_name in ['output', 'output/obfuscated', 'output/keys', 'output/maps']:
            os.makedirs(dir_name, exist_ok=True)

        # Save files with timestamp
        obfuscated_path = f"output/obfuscated/contract_{timestamp}.sol"
        key_path = f"output/keys/key_{timestamp}.txt"
        map_path = f"output/maps/map_{timestamp}.json"

        with open(obfuscated_path, 'w') as f:
            f.write(obfuscated_code)
        with open(key_path, 'w') as f:
            f.write(key.decode())
        with open(map_path, 'w') as f:
            json.dump(obfuscation_map, f, indent=4)

        # Update the text area with the obfuscated code
        self.text_area.delete(1.0, tk.END)
        self.text_area.insert(tk.END, obfuscated_code)

        messagebox.showinfo("Success",
                            f"Obfuscation completed successfully!\n\n"
                            f"Files saved:\n"
                            f"- Obfuscated contract: {obfuscated_path}\n"
                            f"- Encryption key: {key_path}\n"
                            f"- Obfuscation map: {map_path}")


def main():
    app = ObfuscatorGUI()
    app.root.mainloop()


if __name__ == "__main__":
    main()