import base64
import hashlib
import codecs
import os
import json
from cryptography.fernet import Fernet, InvalidToken
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend

# Morse code dictionary
MORSE_CODE_DICT = {
    'A': '.-', 'B': '-...', 'C': '-.-.', 'D': '-..', 'E': '.', 'F': '..-.',
    'G': '--.', 'H': '....', 'I': '..', 'J': '.---', 'K': '-.-', 'L': '.-..',
    'M': '--', 'N': '-.', 'O': '---', 'P': '.--.', 'Q': '--.-', 'R': '.-.',
    'S': '...', 'T': '-', 'U': '..-', 'V': '...-', 'W': '.--', 'X': '-..-',
    'Y': '-.--', 'Z': '--..',
    '1': '.----', '2': '..---', '3': '...--', '4': '....-', '5': '.....',
    '6': '-....', '7': '--...', '8': '---..', '9': '----.', '0': '-----',
    ' ': '/'
}

"""
An advanced encryption/decryption program supporting multiple ciphers,
key management, file I/O, and batch processing.
"""
# --- Helper functions for inputs ---
def prompt_int(prompt, valid_range=None):
    while True:
        try:
            value = int(input(prompt))
            if valid_range and value not in valid_range:
                print(f"Invalid choice. Please select from {valid_range}.")
            else:
                return value
        except ValueError:
            print("Please enter a valid number.")


"""
this function prompts the user for a non-empty input string.
@param prompt: The message displayed to the user when asking for input.
@return: A non-empty string entered by the user.
"""
def prompt_nonempty(prompt):
    while True:
        value = input(prompt).strip()
        if value:
            return value
        print("Input cannot be empty.")


"""
this function prompts the user for a yes/no confirmation.
@param prompt: The message displayed to the user when asking for confirmation.
@return: True if the user confirms with 'y', False if 'n'.
"""
# --- Encryption/Decryption methods ---
def caesar_encrypt(text, shift):
    return ''.join(chr((ord(c) - ord('A') + shift) % 26 + ord('A')) if c.isupper() else
                   chr((ord(c) - ord('a') + shift) % 26 + ord('a')) if c.islower() else c
                   for c in text)


"""
this function decrypts text encrypted with the Caesar cipher using the provided shift.
@param text: The encrypted text that needs to be decrypted.
@param shift: The number of positions each letter in the text was shifted during encryption.
@return: The decrypted text.
"""
def caesar_decrypt(text, shift):
    return caesar_encrypt(text, -shift)

"""
this function encrypts text using the Vigenère cipher with the provided key.
@param text: The plaintext that needs to be encrypted.
@param key: The key used for encryption, which should be a string of letters.
@return: The encrypted text.
"""
def vigenere_encrypt(text, key):
    result, key_index = "", 0
    key = key.lower()
    for c in text:
        if c.isalpha():
            base = 'A' if c.isupper() else 'a'
            shift = ord(key[key_index % len(key)]) - ord('a')
            result += chr((ord(c) - ord(base) + shift) % 26 + ord(base))
            key_index += 1
        else:
            result += c
    return result

"""
this function decrypts text encrypted with the Vigenère cipher using the provided key.
@param text: The encrypted text that needs to be decrypted.
@param key: The key used for decryption, which should match the key used during encryption.
@return: The decrypted text.
"""
def vigenere_decrypt(text, key):
    result, key_index = "", 0
    key = key.lower()
    for c in text:
        if c.isalpha():
            base = 'A' if c.isupper() else 'a'
            shift = ord(key[key_index % len(key)]) - ord('a')
            result += chr((ord(c) - ord(base) - shift) % 26 + ord(base))
            key_index += 1
        else:
            result += c
    return result

"""this function encrypts text using Base64 encoding.
@param text: The plaintext that needs to be encoded.
@return: The Base64 encoded string."""
def base64_encrypt(text):
    return base64.b64encode(text.encode()).decode()


"""this function decrypts Base64 encoded text.
@param text: The Base64 encoded string that needs to be decoded.
@return: The decoded plaintext.
"""
def base64_decrypt(text):
    return base64.b64decode(text.encode()).decode()

"""
this function encrypts text to its hexadecimal representation.
@param text: The plaintext that needs to be converted to hexadecimal.
@return: The hexadecimal representation of the text."""
def hex_encrypt(text):
    return text.encode().hex()


"""this function decrypts hexadecimal text back to its original string.
@param text: The hexadecimal string that needs to be converted back to plaintext.
@return: The original plaintext."""
def hex_decrypt(text):
    return bytes.fromhex(text).decode()


"""this function encrypts text using AES encryption with a password.
@param text: The plaintext that needs to be encrypted.
@param password: The password used to derive the encryption key.
@param use_salt: Boolean indicating whether to use a random salt for key derivation.
@return: The encrypted text, base64 encoded, with the salt prepended if used.
"""


def aes_encrypt(text, password, use_salt=True):
    if use_salt:
        salt = os.urandom(16)
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100000,
            backend=default_backend()
        )
        key = base64.urlsafe_b64encode(kdf.derive(password.encode()))
        cipher = Fernet(key)
        encrypted = cipher.encrypt(text.encode())
        return base64.b64encode(salt + encrypted).decode()
    else:
        key = hashlib.sha256(password.encode()).digest()
        fernet_key = base64.urlsafe_b64encode(key)
        return Fernet(fernet_key).encrypt(text.encode()).decode()

"""this function decrypts AES encrypted text using the provided password.
@param text: The encrypted text, base64 encoded, with the salt prepended if used.
@param password: The password used to derive the decryption key.
@param use_salt: Boolean indicating whether a salt was used during encryption.
@return: The decrypted plaintext, or None if decryption fails (e.g., wrong password).
"""


def aes_decrypt(text, password, use_salt=True):
    try:
        if use_salt:
            data = base64.b64decode(text.encode())
            salt, encrypted = data[:16], data[16:]
            kdf = PBKDF2HMAC(
                algorithm=hashes.SHA256(),
                length=32,
                salt=salt,
                iterations=100000,
                backend=default_backend()
            )
            key = base64.urlsafe_b64encode(kdf.derive(password.encode()))
            return Fernet(key).decrypt(encrypted).decode()
        else:
            key = hashlib.sha256(password.encode()).digest()
            fernet_key = base64.urlsafe_b64encode(key)
            return Fernet(fernet_key).decrypt(text.encode()).decode()
    except InvalidToken:
        return None
    

"""this function encrypts text using the ROT13 cipher.
@param text: The plaintext that needs to be encrypted.
@return: The ROT13 encrypted text.
"""
def rot13_encrypt(text): return codecs.encode(text, 'rot_13')
def rot13_decrypt(text): return codecs.decode(text, 'rot_13')
def morse_encrypt(text): return ' '.join(MORSE_CODE_DICT.get(c.upper(), '') for c in text)
def morse_decrypt(text):
    rev = {v:k for k,v in MORSE_CODE_DICT.items()}
    return ''.join(rev.get(c, '') for c in text.split(' '))
def xor_encrypt(text, key):
    key_long = (key * ((len(text)//len(key))+1))[:len(text)]
    return ''.join(chr(ord(t)^ord(k)) for t,k in zip(text,key_long))
def xor_decrypt(text,key): return xor_encrypt(text,key)


"""this function decrypts text encrypted with the XOR cipher using the provided key.
@param text: The encrypted text that needs to be decrypted.
@param key: The key used for decryption, which should match the key used during encryption.
@return: The decrypted text."""
# --- Key Management ---
KEYS_FILE = "saved_keys.json"
def load_keys():
    if os.path.exists(KEYS_FILE):
        with open(KEYS_FILE,'r',encoding='utf-8') as f:
            return json.load(f)
    return {}


"""this function saves a key for a specific cipher to a JSON file.
@param cipher: The name of the cipher (e.g., "Vigenère", "AES
@param name: The name to associate with the saved key.
@param value: The key value to be saved.
"""
def save_key(cipher, name, value):
    keys = load_keys()
    if cipher not in keys: keys[cipher]={}
    keys[cipher][name]=value
    with open(KEYS_FILE,'w',encoding='utf-8') as f: json.dump(keys,f,indent=2)
    print(f" Saved key '{name}' for {cipher}")


"""this function lists saved keys for a specific cipher.
@param cipher: The name of the cipher to list keys for.
@return: A list of saved key names for the specified cipher."""
def list_saved_keys(cipher):
    keys = load_keys()
    if cipher in keys and keys[cipher]:
        print(f"Saved keys for {cipher}:")
        for i, k in enumerate(keys[cipher].keys(),1):
            print(f"{i}. {k}")
        return list(keys[cipher].keys())
    return []


"""this function retrieves a saved key for a specific cipher by name.
@param cipher: The name of the cipher (e.g., "Vigenère", "AES
@param name: The name associated with the saved key.
@return: The saved key value, or None if not found.
"""
def get_saved_key(cipher, name):
    return load_keys().get(cipher, {}).get(name)


"""this function retrieves a saved key for a specific cipher by name.
@param cipher: The name of the cipher (e.g., "Vigenère", "AES
@param name: The name associated with the saved key.
@return: The saved key value, or None if not found.
"""
# --- File I/O ---
def read_file():
    while True:
        path=input("File path ('cancel' to abort): ").strip()
        if path.lower()=='cancel': return None
        try:
            with open(path,'r',encoding='utf-8') as f: return f.read()
        except Exception as e: print(f" {e}")



def write_file(content, default="output.txt"):
    """this function writes content to a specified file.
    @param content: The content to be written to the file.
    @param default: The default filename to use if the user does not specify one.
    @return: None
    """
    path=input(f"Output file (default: {default}): ").strip() or default
    try:
        with open(path,'w',encoding='utf-8') as f: f.write(content)
        print(f" Saved to {path}")
    except Exception as e: print(f" {e}")

"""this function processes a list of messages using a specified function and arguments.
@param messages: A list of messages to be processed.
@param func: The function to apply to each message (e.g., an encryption/decryption function).
@param args: Additional arguments to pass to the function.
@return: A list of results, with error messages for any failures."""
def batch_process(messages, func, *args):
    results=[]
    for idx,msg in enumerate(messages,1):
        try:
            results.append(func(msg,*args))
            print(f"✓ Message {idx} processed")
        except Exception as e:
            results.append(f"[ERROR: {e}]")
            print(f"✗ Message {idx} failed: {e}")
    return results


"""this function prompts the user for a yes/no confirmation.
@param prompt: The message displayed to the user when asking for confirmation.
@return: True if the user confirms with 'y', False if 'n'."""
# --- Main Program ---
def main():
    print("=== 🔐 Encryption/Decryption Tool ===")
    while True:
        print("\nInput source:\n1. Message In Shell\n2. File\n3. Batch\n4. Exit")
        source_choice = prompt_int("> ", range(1,5))
        if source_choice==4: break

        messages=[]
        batch_mode=False
        if source_choice==1: messages=[input("Enter message: ")]
        elif source_choice==2:
            msg = read_file()
            if msg is None: continue
            messages=[msg]
        elif source_choice==3:
            batch_mode=True
            print("Enter messages (empty line to finish):")
            while True:
                msg=input()
                if not msg: break
                messages.append(msg)
            if not messages: continue

        # Cipher selection
        methods=["Caesar","Vigenère","Base64","AES","ROT13","Morse","Hex","XOR"]
        print("\nEncryption methods:")
        for i,m in enumerate(methods,1): print(f"{i}. {m}")
        cipher_choice = prompt_int("> ", range(1,len(methods)+1))

        input_mode = prompt_int("Mode (1=Encrypt,2=Decrypt): ", [1,2])
        results=[]

        try:
            if cipher_choice==1:  # Caesar
                shift=prompt_int("Shift 1-25: ", range(1,26))
                func = caesar_encrypt if input_mode==1 else caesar_decrypt
                results=batch_process(messages,func,shift) if batch_mode else [func(messages[0],shift)]

            elif cipher_choice==2:  # Vigenère
                print("\nKey options: 1. Manual 2. Saved 3. Save current")
                choice=input("> ").strip()
                key=None
                if choice=="2":
                    saved=list_saved_keys("Vigenère")
                    if saved: key=get_saved_key("Vigenère",saved[prompt_int("Select #: ", range(1,len(saved)+1))-1])
                if not key: key=prompt_nonempty("Enter key: ")
                if choice=="3": save_key("Vigenère", prompt_nonempty("Name: "), key)
                func=vigenere_encrypt if input_mode==1 else vigenere_decrypt
                results=batch_process(messages,func,key) if batch_mode else [func(messages[0],key)]

            elif cipher_choice==3:  # Base64
                func=base64_encrypt if input_mode==1 else base64_decrypt
                results=batch_process(messages,func) if batch_mode else [func(messages[0])]

            elif cipher_choice==4:  # AES
                print("\nPassword options: 1. Manual 2. Saved 3. Save current")
                choice=input("> ").strip()
                password=None
                if choice=="2":
                    saved=list_saved_keys("AES")
                    if saved: password=get_saved_key("AES", saved[prompt_int("Select #: ", range(1,len(saved)+1))-1])
                if not password: password=prompt_nonempty("Enter password: ")
                if choice=="3": save_key("AES", prompt_nonempty("Name: "), password)
                func = aes_encrypt if input_mode==1 else aes_decrypt

                if input_mode==2:  # Decrypt with retry loop
                    results=[]
                    for msg in messages:
                        while True:
                            decrypted=func(msg,password,True)
                            if decrypted is not None:
                                results.append(decrypted)
                                break
                            print("⚠️ Wrong password or corrupted data. Try again.")
                            password=prompt_nonempty("Enter password: ")
                else:
                    results=batch_process(messages,func,password,True) if batch_mode else [func(messages[0],password,True)]

            elif cipher_choice==5:  # ROT13
                func=rot13_encrypt if input_mode==1 else rot13_decrypt
                results=batch_process(messages,func) if batch_mode else [func(messages[0])]

            elif cipher_choice==6:  # Morse
                func=morse_encrypt if input_mode==1 else morse_decrypt
                results=batch_process(messages,func) if batch_mode else [func(messages[0])]

            elif cipher_choice==7:  # Hex
                func=hex_encrypt if input_mode==1 else hex_decrypt
                results=batch_process(messages,func) if batch_mode else [func(messages[0])]

            elif cipher_choice==8:  # XOR
                print("\nKey options: 1. Manual 2. Saved 3. Save current")
                choice=input("> ").strip()
                key=None
                if choice=="2":
                    saved=list_saved_keys("XOR")
                    if saved: key=get_saved_key("XOR", saved[prompt_int("Select #: ", range(1,len(saved)+1))-1])
                if not key: key=prompt_nonempty("Enter key: ")
                if choice=="3": save_key("XOR", prompt_nonempty("Name: "), key)
                func=xor_encrypt if input_mode==1 else xor_decrypt
                results=batch_process(messages,func,key) if batch_mode else [func(messages[0],key)]

            # Display results
            label="Encrypted" if input_mode==1 else "Decrypted"
            print(f"\n {label} Result(s):")
            for idx,res in enumerate(results,1):
                if batch_mode: print(f"\nMessage {idx}:")
                print(res)

            # Save to file
            if input("Save to file? (y/n): ").lower()=='y':
                output="\n\n--- Message Separator ---\n\n".join(results) if batch_mode else results[0]
                write_file(output,f"{label.lower()}_output.txt")

        except Exception as e:
            print(f"Unexpected error: {e}")

        print("\n" + "="*50)

if __name__=="__main__":
    main()
