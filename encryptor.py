from Crypto.Cipher import AES
import os
from dotenv import load_dotenv

# โหลดตัวแปรจากไฟล์ .env
load_dotenv()

# 🗝 ดึง Key และ IV จาก .env (ต้องกำหนดในไฟล์ .env)
SECRET_KEY = os.getenv("SECRET_KEY").encode("utf-8")  # 32-byte Key
IV = os.getenv("IV").encode("utf-8")  # 16-byte IV

# ตรวจสอบความยาวของ Key และ IV
if len(SECRET_KEY) != 32 or len(IV) != 16:
    raise ValueError("SECRET_KEY ต้องยาว 32 bytes และ IV ต้องยาว 16 bytes")

# ✅ ฟังก์ชันเข้ารหัสข้อมูล
def encrypt_data(data: bytes) -> bytes:
    cipher = AES.new(SECRET_KEY, AES.MODE_CBC, IV)
    # 🔹 Padding ให้ครบ 16-byte
    padding = 16 - (len(data) % 16)
    data += bytes([padding]) * padding
    encrypted_data = cipher.encrypt(data)
    return encrypted_data

# 🔓 ฟังก์ชันถอดรหัสข้อมูล
def decrypt_data(encrypted_data: bytes) -> bytes:
    cipher = AES.new(SECRET_KEY, AES.MODE_CBC, IV)
    decrypted_data = cipher.decrypt(encrypted_data)
    # 🔹 ลบ Padding ที่เติมไว้
    padding = decrypted_data[-1]
    decrypted_data = decrypted_data[:-padding]
    return decrypted_data

# ✅ ฟังก์ชันเข้ารหัสไฟล์ (ให้เลือก .enc หรือ .bin)
def encrypt_mode():
    input_file = input("🔹 กรุณาใส่ชื่อไฟล์ที่ต้องการเข้ารหัส: ").strip()
    if not os.path.exists(input_file):
        print("❌ ไม่พบไฟล์ที่ต้องการเข้ารหัส")
        return
    
    # เพิ่มตัวเลือกนามสกุล
    print("🔸 เลือกนามสกุลไฟล์ที่เข้ารหัส:")
    print("1. .enc")
    print("2. .bin")
    ext_choice = input("🔹 กรุณาเลือก (1 หรือ 2): ").strip()
    
    if ext_choice == "1":
        extension = ".enc"
    elif ext_choice == "2":
        extension = ".bin"
    else:
        print("❌ ตัวเลือกไม่ถูกต้อง ใช้ .bin เป็นค่าเริ่มต้น")
        extension = ".bin"
    
    output_file = input_file + extension
    with open(input_file, "rb") as f:
        file_data = f.read()
    encrypted_data = encrypt_data(file_data)
    with open(output_file, "wb") as f:
        f.write(encrypted_data)
    print(f"✅ ไฟล์ถูกเข้ารหัสแล้ว: {output_file}")

# 🔓 ฟังก์ชันถอดรหัสไฟล์ (รองรับทั้ง .enc และ .bin)
def decrypt_mode():
    input_file = input("🔹 กรุณาใส่ชื่อไฟล์ที่ต้องการถอดรหัส: ").strip()
    if not os.path.exists(input_file):
        print("❌ ไม่พบไฟล์ที่ต้องการถอดรหัส")
        return
    
    # ตรวจสอบและลบ .enc หรือ .bin ออก
    if input_file.endswith(".enc"):
        output_file = input_file.replace(".enc", "")
    elif input_file.endswith(".bin"):
        output_file = input_file.replace(".bin", "")
    else:
        print("❌ ไฟล์ต้องมีนามสกุล .enc หรือ .bin")
        return
    
    with open(input_file, "rb") as f:
        encrypted_data = f.read()
    decrypted_data = decrypt_data(encrypted_data)
    with open(output_file, "wb") as f:
        f.write(decrypted_data)
    print(f"✅ ไฟล์ถูกถอดรหัสแล้ว: {output_file}")

# 🔥 เริ่มโปรแกรม
if __name__ == "__main__":
    print("🔹 เลือกโหมดที่ต้องการ:")
    print("1. เข้ารหัสไฟล์ (Encrypt)")
    print("2. ถอดรหัสไฟล์ (Decrypt)")
    choice = input("🔸 กรุณาเลือก (1 หรือ 2): ").strip()
    if choice == "1":
        encrypt_mode()
    elif choice == "2":
        decrypt_mode()
    else:
        print("❌ ตัวเลือกไม่ถูกต้อง")