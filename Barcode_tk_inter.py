from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Hash import SHA
import base64
import hashlib
import tkinter as tk
from tkinter import ttk
import qrcode
from PIL import Image, ImageTk

nomor_pengiriman_entry = None
tanggal_kirim_entry = None
kode_cabang_entry = None
result_label = None
qr_code_label = None
root = None

def encrypt_aes_ocb(data, key):
    cipher = AES.new(key, AES.MODE_OCB)
    ciphertext, tag = cipher.encrypt_and_digest(data.encode('utf-8'))
    return base64.b64encode(cipher.nonce + tag + ciphertext).decode('utf-8')

def calculate_sha1(data):
    sha1_hash = hashlib.sha1(data.encode('utf-8')).digest()
    return base64.b64encode(sha1_hash).decode('utf-8')

def generate_qr_code_with_data(data):
    qr = qrcode.QRCode(
        version=1,
        error_correction=qrcode.constants.ERROR_CORRECT_L,
        box_size=10,
        border=4,
    )
    qr.add_data(data)
    qr.make(fit=True)
    qr_img = qr.make_image(fill_color="black", back_color="white")
    return qr_img, data

def generate_barcode_callback():
    global nomor_pengiriman_entry, tanggal_kirim_entry, kode_cabang_entry, result_label, qr_code_label

    nomor_pengiriman = nomor_pengiriman_entry.get()
    tanggal_kirim = tanggal_kirim_entry.get()
    kode_cabang = kode_cabang_entry.get()
    data_to_encrypt = f"{nomor_pengiriman}-{tanggal_kirim}-{kode_cabang}"
    aes_key = get_random_bytes(32)
    encrypted_data = encrypt_aes_ocb(data_to_encrypt, aes_key)
    sha1_hash = calculate_sha1(data_to_encrypt)
    barcode_data = f"{encrypted_data}-{sha1_hash}"
    result_label.config(text=f"Barcode yang dihasilkan: {barcode_data}")

    # Menghasilkan gambar QR Code dan mendapatkan data barcode
    qr_code_image, barcode_data = generate_qr_code_with_data(barcode_data)
    qr_code_image.save("barcode_qr_code.png")

    # Menampilkan gambar QR Code
    img = ImageTk.PhotoImage(qr_code_image)
    qr_code_label.config(image=img)
    qr_code_label.image = img

    result_label.config(text=f"Barcode yang dihasilkan: {barcode_data}")

if __name__ == "__main__":
    root = tk.Tk()
    root.title("Generate Barcode")

    main_frame = ttk.Frame(root, padding="10")
    main_frame.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))

    nomor_pengiriman_label = ttk.Label(main_frame, text="Nomor Pengiriman:")
    nomor_pengiriman_label.grid(row=0, column=0, sticky=tk.W, pady=5)
    nomor_pengiriman_entry = ttk.Entry(main_frame)
    nomor_pengiriman_entry.grid(row=0, column=1, sticky=(tk.W, tk.E), pady=5)

    tanggal_kirim_label = ttk.Label(main_frame, text="Tanggal Kirim:")
    tanggal_kirim_label.grid(row=1, column=0, sticky=tk.W, pady=5)
    tanggal_kirim_entry = ttk.Entry(main_frame)
    tanggal_kirim_entry.grid(row=1, column=1, sticky=(tk.W, tk.E), pady=5)

    kode_cabang_label = ttk.Label(main_frame, text="Kode Cabang:")
    kode_cabang_label.grid(row=2, column=0, sticky=tk.W, pady=5)
    kode_cabang_entry = ttk.Entry(main_frame)
    kode_cabang_entry.grid(row=2, column=1, sticky=(tk.W, tk.E), pady=5)

    generate_button = ttk.Button(main_frame, text="Generate Barcode", command=generate_barcode_callback)
    generate_button.grid(row=3, column=0, columnspan=2, pady=10)

    result_label = ttk.Label(main_frame, text="")
    result_label.grid(row=4, column=0, columnspan=2, pady=10)

    qr_code_label = ttk.Label(main_frame, text="QR Code")
    qr_code_label.grid(row=5, column=0, columnspan=2, pady=10)

    root.mainloop()
