import os
import tkinter as tk
from tkinter import filedialog, messagebox

# --- Caesar Cipher Class ---
class CaesarCipher:
    def __init__(self):
        self.uk_alphabet = "абвгґдежзийіклмнопрстуфхцчшщьюя"
        self.en_alphabet = "abcdefghijklmnopqrstuvwxyz"

    def validate_key(self, key):
        if not isinstance(key, int):
            raise ValueError("Key must be an integer.")

    def shift_alphabet(self, alphabet, key):
        return alphabet[key:] + alphabet[:key]

    def encrypt(self, text, key, language="en"):
        self.validate_key(key)
        alphabet = self.en_alphabet if language == "en" else self.uk_alphabet
        shifted_alphabet = self.shift_alphabet(alphabet, key)
        table = str.maketrans(alphabet + alphabet.upper(),
                              shifted_alphabet + shifted_alphabet.upper())
        return text.translate(table)

    def decrypt(self, text, key, language="en"):
        return self.encrypt(text, -key, language)

# --- Trithemius Cipher Class ---
class TrithemiusCipher:
    def __init__(self):
        self.uk_alphabet = "абвгґдежзийіклмнопрстуфхцчшщьюя"
        self.en_alphabet = "abcdefghijklmnopqrstuvwxyz"

    def validate_key(self, key):
        if not (isinstance(key, tuple) or isinstance(key, str)):
            raise ValueError("Key must be a tuple (for vector) or a string (for a passphrase).")

    def generate_shift(self, position, key):
        if isinstance(key, tuple):
            if len(key) == 2:
                return key[0] * position + key[1]  # 2D vector
            elif len(key) == 3:
                return key[0] * position ** 2 + key[1] * position + key[2]  # 3D vector
        elif isinstance(key, str):
            return ord(key[position % len(key)])
        raise ValueError("Invalid key format.")

    def encrypt(self, text, key, language="en"):
        self.validate_key(key)
        alphabet = self.en_alphabet if language == "en" else self.uk_alphabet
        result = []
        for i, char in enumerate(text):
            if char.lower() in alphabet:
                shift = self.generate_shift(i, key) % len(alphabet)
                shifted_alphabet = alphabet[shift:] + alphabet[:shift]
                char_map = str.maketrans(alphabet + alphabet.upper(),
                                         shifted_alphabet + shifted_alphabet.upper())
                result.append(char.translate(char_map))
            else:
                result.append(char)
        return ''.join(result)

    def decrypt(self, text, key, language="en"):
        self.validate_key(key)
        alphabet = self.en_alphabet if language == "en" else self.uk_alphabet
        result = []
        for i, char in enumerate(text):
            if char.lower() in alphabet:
                shift = self.generate_shift(i, key) % len(alphabet)
                shifted_alphabet = alphabet[-shift:] + alphabet[:-shift]
                char_map = str.maketrans(alphabet + alphabet.upper(),
                                         shifted_alphabet + shifted_alphabet.upper())
                result.append(char.translate(char_map))
            else:
                result.append(char)
        return ''.join(result)

# --- Poem Cipher Class ---
class PoemCipher:
    def __init__(self):
        self.uk_alphabet = "абвгґдежзийіклмнопрстуфхцчшщьюя"
        self.en_alphabet = "abcdefghijklmnopqrstuvwxyz"

    def validate_key(self, key):
        if not isinstance(key, str) or not key.strip():
            raise ValueError("Key must be a non-empty string (poem).")

    def generate_shift(self, position, poem):
        poem_cleaned = ''.join(filter(str.isalpha, poem.lower()))
        if not poem_cleaned:
            raise ValueError("Poem must contain at least one letter.")
        return ord(poem_cleaned[position % len(poem_cleaned)]) % len(self.en_alphabet)

    def encrypt(self, text, poem, language="en"):
        self.validate_key(poem)
        alphabet = self.en_alphabet if language == "en" else self.uk_alphabet
        result = []
        for i, char in enumerate(text):
            if char.lower() in alphabet:
                shift = self.generate_shift(i, poem) % len(alphabet)
                shifted_alphabet = alphabet[shift:] + alphabet[:shift]
                char_map = str.maketrans(alphabet + alphabet.upper(),
                                         shifted_alphabet + shifted_alphabet.upper())
                result.append(char.translate(char_map))
            else:
                result.append(char)
        return ''.join(result)

    def decrypt(self, text, poem, language="en"):
        self.validate_key(poem)
        alphabet = self.en_alphabet if language == "en" else self.uk_alphabet
        result = []
        for i, char in enumerate(text):
            if char.lower() in alphabet:
                shift = self.generate_shift(i, poem) % len(alphabet)
                shifted_alphabet = alphabet[-shift:] + alphabet[:-shift]
                char_map = str.maketrans(alphabet + alphabet.upper(),
                                         shifted_alphabet + shifted_alphabet.upper())
                result.append(char.translate(char_map))
            else:
                result.append(char)
        return ''.join(result)

# --- File Manager Class ---
class FileManager:
    @staticmethod
    def read_file(filename):
        if not os.path.exists(filename):
            raise FileNotFoundError(f"File {filename} does not exist.")
        with open(filename, 'r', encoding='utf-8') as file:
            return file.read()

    @staticmethod
    def save_file(filename, content):
        with open(filename, 'w', encoding='utf-8') as file:
            file.write(content)

# --- GUI Application ---
class CipherApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Advanced Cipher Application")

        self.caesar_cipher = CaesarCipher()
        self.trithemius_cipher = TrithemiusCipher()
        self.poem_cipher = PoemCipher()
        self.file_manager = FileManager()

        self.text = tk.StringVar()
        self.key = tk.StringVar()
        self.language = tk.StringVar(value="en")
        self.cipher_method = tk.StringVar(value="Caesar")

        # --- GUI Components ---
        self.create_widgets()

    def create_widgets(self):
        # Text Input
        tk.Label(self.root, text="Enter Text:").pack(pady=5)
        self.text_entry = tk.Entry(self.root, textvariable=self.text, width=50)
        self.text_entry.pack(pady=5)

        # Key Input
        tk.Label(self.root, text="Enter Key (int, tuple, passphrase, or poem):").pack(pady=5)
        self.key_entry = tk.Entry(self.root, textvariable=self.key, width=30)
        self.key_entry.pack(pady=5)

        # Language Selection
        tk.Label(self.root, text="Select Language:").pack(pady=5)
        tk.Radiobutton(self.root, text="English", variable=self.language, value="en").pack()
        tk.Radiobutton(self.root, text="Ukrainian", variable=self.language, value="uk").pack()

        # Cipher Method Selection
        tk.Label(self.root, text="Select Cipher Method:").pack(pady=5)
        tk.Radiobutton(self.root, text="Caesar", variable=self.cipher_method, value="Caesar").pack()
        tk.Radiobutton(self.root, text="Trithemius", variable=self.cipher_method, value="Trithemius").pack()
        tk.Radiobutton(self.root, text="Poem", variable=self.cipher_method, value="Poem").pack()

        # Buttons
        tk.Button(self.root, text="Encrypt", command=self.encrypt_text).pack(pady=5)
        tk.Button(self.root, text="Decrypt", command=self.decrypt_text).pack(pady=5)
        tk.Button(self.root, text="Open File", command=self.open_file).pack(pady=5)
        tk.Button(self.root, text="Save File", command=self.save_file).pack(pady=5)
        tk.Button(self.root, text="About", command=self.show_about).pack(pady=5)
        tk.Button(self.root, text="Exit", command=self.root.quit).pack(pady=5)

    def parse_key(self):
        key = self.key.get()
        try:
            if key.startswith("(") and key.endswith(")"):
                return tuple(map(int, key.strip("() ").split(",")))
            elif key.isdigit():
                return int(key)
            else:
                return key  # Assume passphrase or poem
        except Exception:
            raise ValueError("Invalid key format.")

    def encrypt_text(self):
        try:
            key = self.parse_key()
            text = self.text.get()
            language = self.language.get()
            if self.cipher_method.get() == "Caesar":
                result = self.caesar_cipher.encrypt(text, key, language)
            elif self.cipher_method.get() == "Trithemius":
                result = self.trithemius_cipher.encrypt(text, key, language)
            elif self.cipher_method.get() == "Poem":
                result = self.poem_cipher.encrypt(text, key, language)
            else:
                raise ValueError("Invalid cipher method.")
            self.text.set(result)
            messagebox.showinfo("Success", "Text encrypted successfully!")
        except ValueError as e:
            messagebox.showerror("Error", str(e))

    def decrypt_text(self):
        try:
            key = self.parse_key()
            text = self.text.get()
            language = self.language.get()
            if self.cipher_method.get() == "Caesar":
                result = self.caesar_cipher.decrypt(text, key, language)
            elif self.cipher_method.get() == "Trithemius":
                result = self.trithemius_cipher.decrypt(text, key, language)
            elif self.cipher_method.get() == "Poem":
                result = self.poem_cipher.decrypt(text, key, language)
            else:
                raise ValueError("Invalid cipher method.")
            self.text.set(result)
            messagebox.showinfo("Success", "Text decrypted successfully!")
        except ValueError as e:
            messagebox.showerror("Error", str(e))

    def open_file(self):
        file_path = filedialog.askopenfilename()
        if file_path:
            try:
                content = self.file_manager.read_file(file_path)
                self.text.set(content)
                messagebox.showinfo("Success", "File opened successfully!")
            except FileNotFoundError as e:
                messagebox.showerror("Error", str(e))

    def save_file(self):
        file_path = filedialog.asksaveasfilename(defaultextension=".txt",
                                                 filetypes=[("Text files", "*.txt")])
        if file_path:
            content = self.text.get()
            self.file_manager.save_file(file_path, content)
            messagebox.showinfo("Success", "File saved successfully!")

    def show_about(self):
        messagebox.showinfo("About",
                            "Cipher Application v2.1\n"
                            "Developed by Dmytro Mikhno TV-12.\n"
                            "Supports Caesar, Trithemius, and Poem ciphers.\n")

# --- Main Function ---
def main():
    root = tk.Tk()
    app = CipherApp(root)
    root.mainloop()

if __name__ == "__main__":
    main()
