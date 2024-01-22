import base64
import random
import string
import tkinter as tk
from tkinter import messagebox

def random_character_generator(size):
    characters = string.ascii_uppercase + string.digits
    random_str = ''.join(random.choice(characters) for _ in range(size))
    return random_str

def base64_encode(data):
    base64_bytes = base64.b64encode(data.encode('utf-8'))
    base64_text = str(base64_bytes, 'utf-8')
    return base64_text

def cut_text(text, length):
    return text[:length]

def generate_captcha():
    random_characters = random_character_generator(5)
    base64_string = base64_encode(random_characters)
    captcha = cut_text(base64_string, 10)
    return captcha

def verify_captcha(user_input, captcha):
    return user_input == captcha

def show_result(message):
    messagebox.showinfo("Informasi", message)

def regenerate_captcha():
    global captcha
    captcha = generate_captcha()
    captcha_label.config(text="Captcha Anda adalah: " + captcha)
    

def check_captcha():
    global captcha
    captcha = generate_captcha()
    
    def check_button_clicked():
        user_input = entry.get()
        if verify_captcha(user_input, captcha):
            show_result("Captcha benar! Akses diberikan kepada Anda!")
            root.destroy()
        else:
            show_result("Captcha salah! Akses ditolak, Anda harus mencoba lagi.")
            entry.delete(0, 'end')  # Mengosongkan field setelah kesalahan
    
    root = tk.Tk()
    root.title("Verifikasi Captcha")
    
    label = tk.Label(root, text="Selamat datang! Silakan login.")
    label.pack(pady=10)
    
    global captcha_label
    captcha = generate_captcha()
    captcha_label = tk.Label(root, text="Captcha Anda adalah: " + captcha)
    captcha_label.pack(pady=10)
    
    entry = tk.Entry(root)
    entry.pack(pady=10)
    
    check_button = tk.Button(root, text="Cek Captcha", command=check_button_clicked)
    check_button.pack(pady=10)
    
    regenerate_button = tk.Button(root, text="Buat Ulang Captcha", command=regenerate_captcha)
    regenerate_button.pack(pady=10)
    
    root.mainloop()

if __name__ == "__main__":
    check_captcha()
