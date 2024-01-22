from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
import base64
import json
import tkinter as tk
from tkinter import ttk
from tkinter import messagebox

# Fungsi untuk mengenkripsi data JSON dengan AES 256 CTR dan encoding Base64
def encrypt_json(data, key):
    json_string = json.dumps(data)
    nonce = get_random_bytes(8)
    key = key.ljust(32)[:32]
    cipher = AES.new(key.encode('utf-8'), AES.MODE_CTR, nonce=nonce)
    encrypted_data = cipher.encrypt(json_string.encode('utf-8'))
    encrypted_message = base64.b64encode(nonce + encrypted_data).decode('utf-8')
    return encrypted_message

# Fungsi untuk mendekripsi data JSON dengan AES 256 CTR dan decoding Base64
def decrypt_and_display(watermark, key):
    try:
        decoded_watermark = base64.b64decode(watermark.encode('utf-8'))
        nonce = decoded_watermark[:8]
        key = key.ljust(32)[:32]
        cipher = AES.new(key.encode('utf-8'), AES.MODE_CTR, nonce=nonce)
        decrypted_data = cipher.decrypt(decoded_watermark[8:])
        json_data = decrypted_data.decode('utf-8')
        data_object = json.loads(json_data)
        result_text.config(state=tk.NORMAL)
        result_text.delete("1.0", tk.END)
        result_text.insert(tk.END, json.dumps(data_object, indent=2))
        result_text.config(state=tk.DISABLED)

        # Menampilkan simbol "Encrypted"
        encrypted_label.config(text="Watermark Hasil Enkripsi", foreground="red")
    except Exception as e:
        messagebox.showerror("Error", f"Error during decryption: {str(e)}")

def encrypt_and_display():
    username = username_entry.get()
    password = password_entry.get()
    status = status_entry.get()

    data_to_encrypt = {
        "username": username,
        "password": password,
        "status": status
    }

    encryption_key = encryption_key_entry.get()

    try:
        encrypted_data = encrypt_json(data_to_encrypt, encryption_key)
        with open("encrypted_data_watermark.txt", "w") as file:
            file.write(encrypted_data)

        messagebox.showinfo("Success", "Data JSON has been encrypted and saved as a watermark.")
        with open("encrypted_data_watermark.txt", "r") as file:
            encrypted_watermark = file.read()
        decrypt_and_display(encrypted_watermark, encryption_key)

    except Exception as e:
        messagebox.showerror("Error", f"Error during encryption: {str(e)}")

# Main Tkinter window
root = tk.Tk()
root.title("JSON Encryption Tool")

main_frame = ttk.Frame(root, padding="10")
main_frame.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))

# Input Fields
username_label = ttk.Label(main_frame, text="Username :")
username_label.grid(row=0, column=0, sticky=tk.W, pady=5)
username_entry = ttk.Entry(main_frame)
username_entry.grid(row=0, column=1, sticky=(tk.W, tk.E), pady=5)

password_label = ttk.Label(main_frame, text="Password :")
password_label.grid(row=1, column=0, sticky=tk.W, pady=5)
password_entry = ttk.Entry(main_frame, show="*")
password_entry.grid(row=1, column=1, sticky=(tk.W, tk.E), pady=5)

status_label = ttk.Label(main_frame, text="Status :")
status_label.grid(row=2, column=0, sticky=tk.W, pady=5)
status_entry = ttk.Entry(main_frame)
status_entry.grid(row=2, column=1, sticky=(tk.W, tk.E), pady=5)

encryption_key_label = ttk.Label(main_frame, text="Kunci Enkripsi :")
encryption_key_label.grid(row=3, column=0, sticky=tk.W, pady=5)
encryption_key_entry = ttk.Entry(main_frame, show="*")
encryption_key_entry.grid(row=3, column=1, sticky=(tk.W, tk.E), pady=5)

# Action Buttons
encrypt_button = ttk.Button(main_frame, text="Enkripsi Data", command=encrypt_and_display)
encrypt_button.grid(row=4, column=0, columnspan=2, pady=10)

# Result Text
result_label = ttk.Label(main_frame, text="Hasil Deskripsi :")
result_label.grid(row=5, column=0, columnspan=2, pady=5)

result_text = tk.Text(main_frame, width=40, height=10, state=tk.DISABLED)
result_text.grid(row=6, column=0, columnspan=2, pady=5)

# Encrypted Label
encrypted_label = ttk.Label(main_frame, text="", font=("Arial", 12))
encrypted_label.grid(row=7, column=0, columnspan=2, pady=5)

root.mainloop()
