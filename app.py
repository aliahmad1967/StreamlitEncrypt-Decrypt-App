import streamlit as st
import os
import io
import zipfile
import shutil
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend

# الدوال الأساسية
def get_secret_key():
    return st.session_state.get("secret_key", b"0123456789abcdef0123456789abcdef")

def encrypt_data(data, key):
    iv = os.urandom(16)
    cipher = Cipher(algorithms.AES(key), modes.CFB(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    encrypted = encryptor.update(data) + encryptor.finalize()
    return iv + encrypted

def decrypt_data(data, key):
    iv = data[:16]
    encrypted_data = data[16:]
    cipher = Cipher(algorithms.AES(key), modes.CFB(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    decrypted = decryptor.update(encrypted_data) + decryptor.finalize()
    return decrypted

def zip_folder(folder_path):
    zip_buffer = io.BytesIO()
    with zipfile.ZipFile(zip_buffer, 'w', zipfile.ZIP_DEFLATED) as zip_file:
        for root, _, files in os.walk(folder_path):
            for file in files:
                file_path = os.path.join(root, file)
                arcname = os.path.relpath(file_path, folder_path)
                zip_file.write(file_path, arcname)
    return zip_buffer.getvalue()

def decrypt_to_folder(encrypted_file, output_folder, key):
    encrypted_content = encrypted_file.read()
    decrypted_data = decrypt_data(encrypted_content, key)
    with zipfile.ZipFile(io.BytesIO(decrypted_data)) as z:
        z.extractall(output_folder)

def preview_files(folder_path):
    file_count = 0
    for root, _, files in os.walk(folder_path):
        for file in files:
            file_count += 1
            file_path = os.path.join(root, file)
            st.write(f"📄 {file}")
            if file.lower().endswith(('.png', '.jpg', '.jpeg', '.gif')):
                st.image(file_path)
            elif file.lower().endswith(('.mp4', '.mov', '.avi')):
                st.video(file_path)
            elif file.lower().endswith(('.mp3', '.wav', '.ogg')):
                st.audio(file_path)
            elif file.lower().endswith('.pdf'):
                with open(file_path, "rb") as f:
                    st.download_button(label=f"📄 تحميل {file}", data=f, file_name=file, key=file_path)
            elif file.lower().endswith(('.txt', '.log', '.md')):
                with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
                    st.text_area(f"📄 {file}", f.read(), height=200)
            with open(file_path, "rb") as f:
                st.download_button(label=f"⬇️ تحميل {file}", data=f, file_name=file, key=file_path+"download")
    return file_count

def zip_entire_folder(folder_path, zip_path):
    with zipfile.ZipFile(zip_path, 'w', zipfile.ZIP_DEFLATED) as zip_file:
        for root, _, files in os.walk(folder_path):
            for file in files:
                file_path = os.path.join(root, file)
                arcname = os.path.relpath(file_path, folder_path)
                zip_file.write(file_path, arcname)

st.set_page_config(page_title="🔐 تشفير وفك تشفير الملفات", layout="centered")

st.markdown(
    """
    <style>
    body, .css-18e3th9, .css-1d391kg {direction: RTL; text-align: right; font-family: 'Cairo', sans-serif;}
    .stButton>button {
        background-color: #4CAF50;
        color: white;
        border-radius: 12px;
        padding: 10px 20px;
        border: none;
        font-size: 18px;
        transition: all 0.3s ease;
    }
    .stButton>button:hover {
        background-color: #45a049;
        transform: scale(1.05);
    }
    .stFileUploader>div {
        border: 3px dashed #4CAF50;
        border-radius: 15px;
        background-color: #f9f9f9;
        padding: 20px;
        transition: all 0.3s ease;
    }
    .stFileUploader>div:hover {
        background-color: #e6f7e6;
    }
    .stDownloadButton>button {
        background-color: #2196F3;
        color: white;
        border-radius: 12px;
        padding: 10px 20px;
        font-size: 16px;
        transition: all 0.3s ease;
    }
    .stDownloadButton>button:hover {
        background-color: #0b7dda;
        transform: scale(1.05);
    }
    .stTextArea>div>textarea {
        border-radius: 10px;
        border: 2px solid #4CAF50;
    }
    </style>
    <link href="https://fonts.googleapis.com/css2?family=Cairo:wght@400;700&display=swap" rel="stylesheet">
    """,
    unsafe_allow_html=True
)

st.title("🔐 تطبيق تشفير وفك تشفير الملفات")

with st.expander("🔑 تعيين مفتاح (اختياري)"):
    key_input = st.text_input("أدخل مفتاح التشفير (32 حرف):", type="password")
    if len(key_input) == 32:
        st.session_state["secret_key"] = key_input.encode()
        st.success("✅ تم تعيين المفتاح!")
    elif key_input:
        st.warning("⚠️ يجب أن يكون المفتاح 32 حرف بالضبط.")

# تشفير مجلد
st.markdown("---")
st.subheader("🔒 تشفير مجلد")
folder_path = st.text_input("📁 أدخل مسار المجلد الذي تريد تشفيره:")

if st.button("🔒 ابدأ التشفير"):
    if folder_path and os.path.isdir(folder_path):
        key = get_secret_key()
        zipped_data = zip_folder(folder_path)
        encrypted_data = encrypt_data(zipped_data, key)

        st.download_button("⬇️ تحميل الملف المشفر", data=encrypted_data, file_name="encrypted_file.bin", key="encrypted_download")
        st.success("✅ تم التشفير بنجاح!")
    else:
        st.error("❌ تحقق من صحة المجلد.")

# فك تشفير ملف
st.markdown("---")
st.subheader("🔓 فك تشفير الملف")
uploaded_file = st.file_uploader("📂 اسحب وأسقط الملف المشفر هنا، أو اضغط للرفع:")

if uploaded_file:
    output_folder = st.text_input("📂 أدخل مسار مجلد الحفظ:")

    if st.button("🔓 ابدأ فك التشفير"):
        if output_folder:
            os.makedirs(output_folder, exist_ok=True)
            try:
                key = get_secret_key()
                decrypt_to_folder(uploaded_file, output_folder, key)
                st.success("✅ تم فك التشفير بنجاح!")

                with st.expander("👁️ معاينة الملفات:"):
                    file_count = preview_files(output_folder)
                    st.info(f"📊 عدد الملفات المفككة: {file_count}")

                    zip_path = os.path.join(output_folder, "all_files.zip")
                    zip_entire_folder(output_folder, zip_path)

                    with open(zip_path, "rb") as f:
                        st.download_button(label="⬇️ تحميل كل الملفات كمجلد مضغوط", data=f, file_name="all_files.zip", key="all_files_zip")

            except Exception as e:
                st.error(f"❌ خطأ: {e}")
        else:
            st.error("❌ الرجاء تحديد مسار مجلد الحفظ.")
