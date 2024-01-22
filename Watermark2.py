from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
import base64
import json

# Fungsi untuk mengenkripsi data JSON dengan AES 256 CTR dan encoding Base64
def encrypt_json(data, key):
    # Mengonversi data JSON menjadi string
    json_string = json.dumps(data)

    # Menghasilkan nonce (IV) dengan panjang 8 byte
    nonce = get_random_bytes(8)

    # Mengonversi kunci menjadi panjang 32 byte
    key = key.ljust(32)[:32]

    # Membuat objek cipher AES 256 CTR
    cipher = AES.new(key.encode('utf-8'), AES.MODE_CTR, nonce=nonce)
    
    # Melakukan enkripsi
    encrypted_data = cipher.encrypt(json_string.encode('utf-8'))

    # Menggabungkan nonce, data terenkripsi, dan tag menjadi satu string
    encrypted_message = base64.b64encode(nonce + encrypted_data).decode('utf-8')

    return encrypted_message

# Fungsi untuk mendekripsi data JSON dengan AES 256 CTR dan decoding Base64
def decrypt_and_display(watermark, key):
    # Mengonversi watermark dari Base64
    decoded_watermark = base64.b64decode(watermark.encode('utf-8'))

    # Mengambil nonce (IV) dari watermark
    nonce = decoded_watermark[:8]

    # Mengonversi kunci menjadi panjang 32 byte
    key = key.ljust(32)[:32]

    # Membuat objek cipher AES 256 CTR
    cipher = AES.new(key.encode('utf-8'), AES.MODE_CTR, nonce=nonce)

    # Melakukan dekripsi
    decrypted_data = cipher.decrypt(decoded_watermark[8:])

    # Mengonversi data terdekripsi dari bytes ke string JSON
    json_data = decrypted_data.decode('utf-8')

    # Mengonversi string JSON ke objek Python
    data_object = json.loads(json_data)

    # Menampilkan hasil dekripsi
    print("Hasil Dekripsi:")
    print(json.dumps(data_object, indent=2))

# Pengguna memasukkan data JSON yang akan dienkripsi
username = input("Masukkan username: ")
password = input("Masukkan password: ")
status = input("Masukkan status: ")

data_to_encrypt = {
    "username": username,
    "password": password,
    "status": status
}

# Kunci enkripsi (Anda dapat mengganti kunci ini sesuai kebutuhan)
encryption_key = input("Masukkan kunci enkripsi: ")

# Enkripsi data JSON dan simpan sebagai watermark
encrypted_data = encrypt_json(data_to_encrypt, encryption_key)

# Simpan sebagai watermark (contoh: file)
with open("encrypted_data_watermark.txt", "w") as file:
    file.write(encrypted_data)

print("Data JSON telah dienkripsi dan disimpan sebagai watermark.")

# Baca watermark dari file (atau sesuaikan sumbernya)
with open("encrypted_data_watermark.txt", "r") as file:
    encrypted_watermark = file.read()

# Dekripsi dan tampilkan hasilnya
decrypt_and_display(encrypted_watermark, encryption_key)
