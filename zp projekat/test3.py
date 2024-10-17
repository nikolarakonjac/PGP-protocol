import hashlib
import os
import tkinter as tk
from tkinter import messagebox
from collections import namedtuple
from tkinter import ttk
import time
from datetime import datetime
from cryptography.hazmat.primitives.asymmetric import padding as asym_padding
from cryptography.hazmat.primitives import serialization, hashes, padding as sym_padding
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.backends import default_backend
import base64

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

# Key structure to store the generated key data
KeyStructure = namedtuple('KeyStructure', ['redni_broj_counter', 'timestamp', 'public_key_pem', 'private_key_pem',
                                           'keyid', 'email', 'password', 'key_size', 'hashed_password', 'encrypted_private_key_pem'])

PublicKeyStructure = namedtuple("PublicKeyStructure", ["timestamp", "email", "public_key"])


private_key_ring = []
public_key_ring = []
redni_broj_counter = 0  # Counter for redniBroj

def calculate_keyid(public_key):
    public_key_bytes = public_key.public_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    return public_key_bytes[-8:]

def readable_timestamp(timestamp):
    return datetime.fromtimestamp(timestamp).strftime('%Y-%m-%d %H:%M:%S')


def encrypt_data(data, key):
    # Generate a random IV
    iv = os.urandom(16)

    # Create cipher configuration
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()

    # Pad data to be a multiple of block size
    padder = sym_padding.PKCS7(algorithms.AES.block_size).padder()
    padded_data = padder.update(data) + padder.finalize()

    # Encrypt data
    encrypted_data = encryptor.update(padded_data) + encryptor.finalize()

    # Prepend IV to encrypted data
    encrypted_data_with_iv = iv + encrypted_data
    return base64.b64encode(encrypted_data_with_iv)  # Return base64 encoded encrypted data

def decrypt_data(encrypted_data, key):
    # Decode the base64 encoded encrypted data
    encrypted_data = base64.b64decode(encrypted_data)

    # Extract the IV from the beginning of the data
    iv = encrypted_data[:16]
    encrypted_data = encrypted_data[16:]

    # Create cipher configuration
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()

    # Decrypt data
    decrypted_padded_data = decryptor.update(encrypted_data) + decryptor.finalize()

    # Remove padding
    unpadder = sym_padding.PKCS7(algorithms.AES.block_size).unpadder()
    decrypted_data = unpadder.update(decrypted_padded_data) + unpadder.finalize()
    return decrypted_data


# Function to handle generating a new key pair
def generate_new_keys():
    # Create a new window for key generation
    key_generation_window = tk.Toplevel(root)
    key_generation_window.title("Generate New Pair of Keys")

    # Create a frame for the input fields and labels
    frame = tk.Frame(key_generation_window)
    frame.pack(padx=50, pady=50)

    # Label and input for "Ime"
    ime_label = tk.Label(frame, text="Ime:")
    ime_label.grid(row=0, column=0, padx=5, pady=5)
    ime_entry = tk.Entry(frame)
    ime_entry.grid(row=0, column=1, padx=5, pady=5)

    # Label and input for "Mejl"
    mejl_label = tk.Label(frame, text="Mejl:")
    mejl_label.grid(row=1, column=0, padx=5, pady=5)
    mejl_entry = tk.Entry(frame)
    mejl_entry.grid(row=1, column=1, padx=5, pady=5)

    # Label and dropdown for "Velicina Kljuca"
    velicina_label = tk.Label(frame, text="Velicina Kljuca:")
    velicina_label.grid(row=2, column=0, padx=5, pady=5)
    velicina_var = tk.StringVar(value="1024")
    velicina_dropdown = ttk.Combobox(frame, textvariable=velicina_var)
    velicina_dropdown['values'] = ("1024", "2048")
    velicina_dropdown.grid(row=2, column=1, padx=5, pady=5)

    def generate_and_store_keys():
        global redni_broj_counter
        name = ime_entry.get()
        email = mejl_entry.get()
        key_size = velicina_var.get()

        # Create a new window for password input
        password_window = tk.Toplevel(key_generation_window)
        password_window.title("Enter Password")

        # Label and input for password
        lozinka_label = tk.Label(password_window, text="Enter Password:")
        lozinka_label.pack(padx=5, pady=5)
        lozinka_entry = tk.Entry(password_window, show="*")
        lozinka_entry.pack(padx=5, pady=5)



        def on_ok():
            global redni_broj_counter
            password = lozinka_entry.get()

            # Key generation logic
            if key_size == "1024":
                private_key = rsa.generate_private_key(
                    public_exponent=65537,
                    key_size=1024,
                    backend=default_backend(),
                )
            else:
                private_key = rsa.generate_private_key(
                    public_exponent=65537,
                    key_size=2048,
                    backend=default_backend(),
                )

            public_key = private_key.public_key()

            # Serialize the private key to PEM format
            private_key_pem = private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.TraditionalOpenSSL,
                encryption_algorithm=serialization.NoEncryption()
            )

            public_key_pem = public_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            )

            sha1_hash = hashlib.sha1()
            sha1_hash.update(password.encode('utf-8'))
            hashed_password = sha1_hash.digest()

            # Ensure the key is the correct length for AES
            key = hashed_password[:16]  # AES requires 16, 24, or 32 bytes

            # Encrypt the private key PEM format
            encrypted_private_key_pem = encrypt_data(private_key_pem, key)  # koristi se AES algoritam za sifrovanje

            # Store key data in KeyStructure
            structure1 = KeyStructure(redni_broj_counter, time.time(), public_key_pem, private_key_pem,
                                      calculate_keyid(public_key), email, password, key_size,
                                      hashed_password, encrypted_private_key_pem)

            private_key_ring.append(structure1)
            redni_broj_counter += 1

            password_window.destroy()
            show_key_ring()

        # Button to submit the password
        ok_button = tk.Button(password_window, text="OK", command=on_ok)
        ok_button.pack(pady=10)

    # Button to generate the key pair
    generate_button = tk.Button(frame, text="Generate Keys", command=generate_and_store_keys)
    generate_button.grid(row=3, columnspan=2, pady=20)

def show_key_ring():
    # Create a new window to display the generated keys
    key_ring_window = tk.Toplevel(root)
    key_ring_window.title("Generated Keys")

    # Text widget to display the key data
    text_widget = tk.Text(key_ring_window, wrap=tk.WORD, width=100, height=30)
    text_widget.pack(padx=10, pady=10, fill=tk.BOTH, expand=True)

    # Display key data in the Text widget
    for ks in private_key_ring:
        key_info = f"""
           Redni Broj: {ks.redni_broj_counter}
           Timestamp: {readable_timestamp(ks.timestamp)}
           Email: {ks.email}
           Key Size: {ks.key_size}
           Password: {ks.password}
           Hashed password : {ks.hashed_password.hex()}
           Key ID: {base64.b64encode(ks.keyid).decode()}
           Public Key: {ks.public_key_pem.decode()}
           Private Key: {ks.private_key_pem.decode()}
           Encrypted private_key_pem: {ks.encrypted_private_key_pem}
           {'-' * 80}
           """
        text_widget.insert(tk.END, key_info + "\n")

    # Make the text read-only
    text_widget.config(state=tk.DISABLED)




# Function to handle message sending with signing or encryption
def send_message():
    message = message_entry.get()
    passwordForKeyPair = passwordForChosenKeyPairEntry.get()
    pairOfKeysNumber = int(chosen_pair_of_keys_entry.get())
    combined_message = message.encode('utf-8')


    if (pairOfKeysNumber < 0 or pairOfKeysNumber >= len(private_key_ring)):
        messagebox.showwarning("Input Error", "Invalid number for key pair number")
        return


    if not message:
        messagebox.showwarning("Input Error", "Please enter a message before sending.")
        return


    if sign_var.get() == 1:
        # POTPIS PORUKE
        print("Message will be signed.")
        # Placeholder for message signature logic

        #unesi sifru

        #hesiraj sifru
        sha1_hash = hashlib.sha1()  #160 bita je hash
        sha1_hash.update(passwordForKeyPair.encode('utf-8'))    #pretvara string u bajtove; prosledjuje sifru objektu SHA na procesiranje
        hashed_passwordForKeyPair = sha1_hash.digest()  # finalizira proces hesiranja i vraca bajtove


        #proveri sifru da li se poklapa
        hashed_passwordFromKeyRing = private_key_ring[pairOfKeysNumber].hashed_password


        if(hashed_passwordFromKeyRing != hashed_passwordForKeyPair):
            messagebox.showwarning("Data Error", "Wrong password for chosen key pair")
            return

        #ako se poklapa desifruj privatni kljuc pem

        key = hashed_passwordForKeyPair[:16]

        #ovim privatnim kljucem treba da se sifruje hes poruke
        decryptedPrivateKeyPEM = decrypt_data(private_key_ring[pairOfKeysNumber].encrypted_private_key_pem, key)   # AES dekripcija

        # Load the decrypted private key from PEM format
        decryptedPrivateKey = serialization.load_pem_private_key(
            decryptedPrivateKeyPEM,
            password=None,  # No password since it's already decrypted
            backend=default_backend()
        )

        #hash poruke koja ce se poslati
        sha1_hash = hashlib.sha1()
        sha1_hash.update(message.encode('utf-8'))
        hashed_message = sha1_hash.digest()

        #hasirana poruka koja je kriptovana privatnim kljucem rsa algoritmom
        signedMessage = decryptedPrivateKey.sign(
            hashed_message,
            asym_padding.PKCS1v15(),  # PKCS1v15 padding for RSA signing
            hashes.SHA1()  # Use SHA-1 for the message hash
        )

        # print(signedMessage)

        #konkatenira se sifrovani potpis sa originalnom porukom
        #treba da se konkatenira signedMessage i message

        delimiter1 = b'---END_OF_SIGNATURE---'
        delimiter2 = b'---END_OF_NUMBER---'
        number_bytes = str(pairOfKeysNumber).encode('utf-8')
        combined_message = signedMessage + delimiter1 + number_bytes + delimiter2 + message.encode('utf-8')


        # print(combined_message)

    if encrypt_var.get() == 1:
        # TAJNOST PORUKE
        message_receiver_number_str = message_receiver_number_entry.get()
        if not message_receiver_number_str:
            messagebox.showwarning("Input Error", "Please enter a message receiver number.")
            return

        message_receiver_number = int(message_receiver_number_entry.get())



        #generisemo sesijski kljuc za aes
        aes_key = os.urandom(16)

        #poruka se sifruje
        encrypted_combined_message = encrypt_data(combined_message, aes_key)  #ulaz u encrypt_data mora da bude bite


        #sesijski kljuc se sifruje javnim kljucem korisnika kome saljemo poruku


        if (message_receiver_number < 0 or message_receiver_number >= len(public_key_ring)):
            messagebox.showwarning("Input Error", "Invalid number for message receiver number")
            return

        message_receiver_public_key = load_rsa_public_key(public_key_ring[message_receiver_number].public_key)

        encrypted_aes_key = message_receiver_public_key.encrypt(
            aes_key,
            asym_padding.OAEP(  # OAEP padding za RSA alg
                mgf=asym_padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )

        #konkatenira se sifrovani kljuc na sifrovanu poruku
        encoded_combined_message = base64.b64encode(encrypted_combined_message).decode('utf-8')
        encoded_aes_key = base64.b64encode(encrypted_aes_key).decode('utf-8')


        concatenated_message = f"{encoded_combined_message}|{encoded_aes_key}|{message_receiver_number}"

        write_message_to_file(concatenated_message)




def write_message_to_file(concatenated_message):
    # Get the path to the user's desktop
    desktop_path = os.path.join(os.path.join(os.environ['USERPROFILE']), 'Desktop')

    # File name
    file_path = os.path.join(desktop_path, "sendMessage.txt")

    try:
        # Write concatenated_message to the file
        with open(file_path, 'w') as file:
            file.write(concatenated_message)
        messagebox.showwarning("Info", f"Message successfully written to {file_path}")
    except Exception as e:
        messagebox.showwarning("Info", f"ERROR. message not send")

def load_rsa_public_key(public_key_str):
    # Convert the base64-encoded public key to PEM format by adding the necessary headers
    public_key_pem = f"-----BEGIN PUBLIC KEY-----\n{public_key_str}\n-----END PUBLIC KEY-----"

    # Load the public key
    public_key = serialization.load_pem_public_key(
        public_key_pem.encode('utf-8'),
        backend=default_backend()
    )
    return public_key

def export_public_key():
    print("hi")
    public_key_number_string = public_key_number_for_export_entry.get()

    if not public_key_number_string:
        messagebox.showwarning("Input Error", "You have to fill public key number for export")
        return


    public_key_number = int(public_key_number_for_export_entry.get())

    if(public_key_number < 0 or public_key_number >= len(private_key_ring)):
        messagebox.showwarning("Input Error", "Invalid number for public key number")
        return

    public_key_pem_for_export = private_key_ring[public_key_number].public_key_pem

    # Define file path on the desktop
    desktop_path = os.path.join(os.path.expanduser("~"), "Desktop")
    file_name = "exportedPublicKeys.txt"
    file_path = os.path.join(desktop_path, file_name)

    # Write user email and public key to the file
    with open(file_path, 'w') as f:
        f.write(f"User Email: {private_key_ring[public_key_number].email}\n")
        f.write("Public Key:\n")
        f.write(public_key_pem_for_export.decode('utf-8'))

    tk.messagebox.showinfo("Success", f"Public key exported successfully to {file_path}!")


def import_public_keys():
    file_path = "C:/Users/Nikola/Desktop/exportedPublicKeys.txt"

    with open(file_path, 'r') as file:
        lines = file.readlines()

    email_and_keys = []
    current_email = None
    current_public_key = []

    for line in lines:
        line = line.strip()

        # Identify user email
        if line.startswith("User Email:"):
            if current_email and current_public_key:
                # Save previous email and public key
                email_and_keys.append((current_email, ''.join(current_public_key).strip()))

            # Start new email and public key
            current_email = line.replace("User Email:", "").strip()
            current_public_key = []

        # Capture public key content, ignoring the BEGIN/END lines
        elif line.startswith("-----BEGIN PUBLIC KEY-----"):
            current_public_key = []
        elif line.startswith("-----END PUBLIC KEY-----"):
            pass
        else:
            # Accumulate public key lines
            current_public_key.append(line)

    # Handle the last public key in the file
    if current_email and current_public_key:
        email_and_keys.append((current_email, ''.join(current_public_key).strip()))


    for x in email_and_keys:
        email = x[0]
        key = x[1]

        structure = PublicKeyStructure(time.time(), email, key)

        public_key_ring.append(structure)


def show_public_key_ring():
    public_key_ring_window = tk.Toplevel(root)
    public_key_ring_window.title("public key ring")

    # Text widget to display the key data
    text_widget = tk.Text(public_key_ring_window, wrap=tk.WORD, width=100, height=30)
    text_widget.pack(padx=10, pady=10, fill=tk.BOTH, expand=True)

    # Display key data in the Text widget
    for ks in public_key_ring:
        key_info = f"""
               Timestamp: {readable_timestamp(ks.timestamp)}
               Email: {ks.email}
               Public Key: {ks.public_key}
               {'-' * 80}
               """
        text_widget.insert(tk.END, key_info + "\n")

    # Make the text read-only
    text_widget.config(state=tk.DISABLED)


def receive_message():
    print("receive message")

    desktop_path = os.path.join(os.path.join(os.environ['USERPROFILE']), 'Desktop')

    # File name
    file_path = os.path.join(desktop_path, "sendMessage.txt")

    try:
        # Read the concatenated message from the file
        with open(file_path, 'r') as file:
            concatenated_message = file.read().strip()

        # Split the concatenated message into parts
        parts = concatenated_message.split('|')

        if len(parts) != 3:
            raise ValueError("The concatenated message format is invalid.")

        # Extract and decode the parts
        decoded_combined_message = base64.b64decode(parts[0])
        decoded_aes_key = base64.b64decode(parts[1])
        message_receiver_number = int(parts[2])

        receiver_private_key_pem = private_key_ring[message_receiver_number].private_key_pem

        receiver_private_key = serialization.load_pem_private_key(
            receiver_private_key_pem,
            password=None,  # Assuming the key is not password protected
            backend=default_backend()
        )

        decrypted_aes_key = receiver_private_key.decrypt(
            decoded_aes_key,
            asym_padding.OAEP(
                mgf=asym_padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )

        decrypted_combined_message = decrypt_data(decoded_combined_message, decrypted_aes_key)

        delimiter1 = b'---END_OF_SIGNATURE---'
        delimiter2 = b'---END_OF_NUMBER---'

        parts = decrypted_combined_message.split(delimiter1)

        if len(parts) != 2:
            raise ValueError("Invalid message format. Delimiter not found or incorrect.")

        signedMessage = parts[0]
        remainder = parts[1]

        parts = remainder.split(delimiter2)

        if len(parts) != 2:
            raise ValueError("Invalid message format. Delimiter not found or incorrect.")

        number = int(parts[0].decode('utf-8'))
        originalMessage = parts[1].decode('utf-8')

        print('original message: ')
        print(originalMessage)

        #hes originalne poruke

        sha1_hash = hashlib.sha1()
        sha1_hash.update(originalMessage.encode('utf-8'))
        hashed_original_message = sha1_hash.digest()

        # provera potpisa poruke -> dekriptujemo signedMessage javnim kljucem posiljaoca i tu dobijemo hesiranu poruku

        print("number")
        print(number)

        sender_public_key = load_rsa_public_key(public_key_ring[0].public_key)

        sender_email = public_key_ring[0].email

        try:
            sender_public_key.verify(
                signedMessage,
                hashed_original_message,
                asym_padding.PKCS1v15(),
                hashes.SHA1()
            )
            print("potpis se poklapa")
            messagebox.showwarning("Message Signature", "Message fits to the signature\n "
                                                        f"message: {originalMessage}\n"
                                                        f"sender: {sender_email}")
        except Exception as e:
            messagebox.showwarning("Message Signature", "Message does not fit to the signature")


    except Exception as e:
        print(f"Failed to read or process the message: {e}")


# Create the main window
root = tk.Tk()
root.title("Message Signature & Encryption")

# Label and input field for the message
message_label = tk.Label(root, text="Your message:")
message_label.pack(padx=20, pady=5)

message_entry = tk.Entry(root, width=50)
message_entry.pack(padx=20, pady=5)

chosen_pair_of_keys_label = tk.Label(root, text="chose pair of keys")
chosen_pair_of_keys_label.pack(padx=20, pady=5)

chosen_pair_of_keys_entry = tk.Entry(root, width=5)
chosen_pair_of_keys_entry.pack(padx=20, pady=5)


passwordForChosenKeyPairLabel = tk.Label(root, text="password for key pair")
passwordForChosenKeyPairLabel.pack(padx=20, pady=5)

passwordForChosenKeyPairEntry = tk.Entry(root, width=20)
passwordForChosenKeyPairEntry.pack(padx=20, pady=5)

# Checkbox for message signature
sign_var = tk.IntVar()  # Holds the state of the checkbox (0 = unchecked, 1 = checked)
signature_checkbox = tk.Checkbutton(root, text="Message Signature", variable=sign_var)
signature_checkbox.pack(padx=20, pady=5)

# Checkbox for message encryption
encrypt_var = tk.IntVar()  # Holds the state of the checkbox (0 = unchecked, 1 = checked)
encryption_checkbox = tk.Checkbutton(root, text="Message Encryption", variable=encrypt_var)
encryption_checkbox.pack(padx=20, pady=5)

# Button to generate a new pair of keys
generate_keys_button = tk.Button(root, text="Generate New Pair of Keys", command=generate_new_keys)
generate_keys_button.pack(padx=20, pady=10)

# Button to send the message
send_message_button = tk.Button(root, text="Send Message", command=send_message)
send_message_button.pack(padx=20, pady=10)


# ----------------------EXPORT-----------------------------------------------------
public_key_number_for_export_label = tk.Label(root, text="public key number for export")
public_key_number_for_export_label.pack(padx=20, pady=10)

public_key_number_for_export_entry = tk.Entry(root, width=5)
public_key_number_for_export_entry.pack(padx=20, pady=10)

export_public_key_button = tk.Button(root, text="export public key", command=export_public_key)
export_public_key_button.pack(padx=20, pady=10)


# --------------------------------- IMPORT --------------------------------------------------

import_public_keys_button = tk.Button(root, text="import public keys", command=import_public_keys)
import_public_keys_button.pack(padx=20, pady=10)

#----------------------------- SHOW PUBLIC KEY RING -----------------------------------

show_public_key_ring_button = tk.Button(root, text="show public key ring", command=show_public_key_ring)
show_public_key_ring_button.pack(padx=20, pady=10)


message_receiver_number_label = tk.Label(root, text="message receiver number")
message_receiver_number_label.pack(padx=20, pady=10)

message_receiver_number_entry = tk.Entry(root, width=5)
message_receiver_number_entry.pack(padx=20, pady=5)

receive_message_button = tk.Button(root, text="receive message", command=receive_message)
receive_message_button.pack(padx=20, pady=10)

# Start the Tkinter event loop
root.mainloop()
