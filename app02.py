import streamlit as st
import os
import io
import zipfile
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
import base64

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

def zip_files(uploaded_files):
    zip_buffer = io.BytesIO()
    with zipfile.ZipFile(zip_buffer, 'w', zipfile.ZIP_DEFLATED) as zip_file:
        for uploaded_file in uploaded_files:
            zip_file.writestr(uploaded_file.name, uploaded_file.read())
    return zip_buffer.getvalue()

def zip_folder(folder_path):
    zip_buffer = io.BytesIO()
    with zipfile.ZipFile(zip_buffer, 'w', zipfile.ZIP_DEFLATED) as zip_file:
        for root, _, files in os.walk(folder_path):
            for file in files:
                file_path = os.path.join(root, file)
                arcname = os.path.relpath(file_path, folder_path)
                zip_file.write(file_path, arcname)
    return zip_buffer.getvalue()

def extract_zip_and_display(zip_data):
    with zipfile.ZipFile(io.BytesIO(zip_data)) as z:
        for file_name in z.namelist():
            st.write(f"📄 {file_name}")
            file_data = z.read(file_name)
            if file_name.endswith(('.png', '.jpg', '.jpeg', '.gif')):
                st.image(file_data)
            elif file_name.endswith(('.mp4', '.webm', '.ogg')):
                st.video(file_data)
            elif file_name.endswith(('.mp3', '.wav', '.ogg')):
                st.audio(file_data)
            elif file_name.endswith('.pdf'):
                st.download_button(f"⬇️ تحميل {file_name}", file_data, file_name)
                st.write("📖 لا يمكن عرض PDF مباشرًا، يرجى التحميل.")
            elif file_name.endswith('.txt'):
                st.text(file_data.decode(errors='ignore'))
            else:
                st.download_button(f"⬇️ تحميل {file_name}", file_data, file_name)

def save_decrypted_folder(zip_data, output_folder):
    with zipfile.ZipFile(io.BytesIO(zip_data)) as z:
        z.extractall(output_folder)

st.set_page_config(page_title="تشفير وفك تشفير الملفات", layout="centered")

st.markdown(
    """
    <style>
    body, .css-18e3th9, .css-1d391kg {direction: RTL; text-align: right;}
    """,
    unsafe_allow_html=True
)

lang = st.sidebar.selectbox("🌐 اختر اللغة", ["العربية", "English"])

if lang == "العربية":
    t = {
        "title": "🔐 تطبيق تشفير وفك تشفير الملفات",
        "upload": "📂 الرجاء سحب وإفلات الملفات هنا:",
        "encrypt": "🔒 تشفير الملفات",
        "decrypt": "🔓 فك تشفير الملفات",
        "folder_encrypt": "🔒 تشفير مجلد كامل",
        "folder_decrypt": "🔓 فك تشفير مجلد مشفر",
        "success_upload": "✅ تم تحميل الملفات بنجاح!",
        "success_encrypt": "✅ تم التشفير بنجاح!",
        "success_decrypt": "✅ تم فك التشفير بنجاح!",
        "error": "❌ خطأ: الملف غير صالح أو مشفر بمفتاح مختلف.",
        "download_encrypted": "⬇️ تحميل الملف المشفر",
        "download_decrypted": "⬇️ تحميل الملفات المفكوكة",
        "set_key": "🔑 تعيين مفتاح مخصص (اختياري)",
        "key_input": "أدخل مفتاح التشفير (32 حرف):",
        "show_files": "📂 عرض الملفات المفكوكة",
        "folder_path": "📁 أدخل مسار المجلد المحلي لتشفيره:",
        "output_folder": "📂 أدخل مسار المجلد لاستخراج الملفات المفكوكة:"
    }
else:
    t = {
        "title": "🔐 File Encryption & Decryption App",
        "upload": "📂 Please drag and drop files here:",
        "encrypt": "🔒 Encrypt Files",
        "decrypt": "🔓 Decrypt Files",
        "folder_encrypt": "🔒 Encrypt Entire Folder",
        "folder_decrypt": "🔓 Decrypt Encrypted Folder",
        "success_upload": "✅ Files uploaded successfully!",
        "success_encrypt": "✅ Encryption successful!",
        "success_decrypt": "✅ Decryption successful!",
        "error": "❌ Error: Invalid file or wrong key.",
        "download_encrypted": "⬇️ Download Encrypted File",
        "download_decrypted": "⬇️ Download Decrypted Files",
        "set_key": "🔑 Set Custom Key (Optional)",
        "key_input": "Enter encryption key (32 chars):",
        "show_files": "📂 Show Decrypted Files",
        "folder_path": "📁 Enter local folder path to encrypt:",
        "output_folder": "📂 Enter local folder path to extract decrypted files:"
    }

st.title(t["title"])

with st.expander(t["set_key"]):
    key_input = st.text_input(t["key_input"], type="password")
    if len(key_input) == 32:
        st.session_state["secret_key"] = key_input.encode()
        st.success("✅ Key set successfully!")
    elif key_input:
        st.warning("⚠️ Key must be exactly 32 characters.")

uploaded_files = st.file_uploader(t["upload"], accept_multiple_files=True)

if uploaded_files:
    st.success(t["success_upload"])

    col1, col2 = st.columns(2)

    with col1:
        if st.button(t["encrypt"]):
            key = get_secret_key()
            zipped_data = zip_files(uploaded_files)
            encrypted_data = encrypt_data(zipped_data, key)

            b64 = base64.b64encode(encrypted_data).decode()
            href = f'<a href="data:file/octet-stream;base64,{b64}" download="encrypted_file.bin">{t["download_encrypted"]}</a>'
            st.markdown(href, unsafe_allow_html=True)
            st.success(t["success_encrypt"])

    with col2:
        if st.button(t["decrypt"]):
            key = get_secret_key()
            encrypted_file = uploaded_files[0]
            encrypted_content = encrypted_file.read()

            try:
                decrypted_data = decrypt_data(encrypted_content, key)
                b64 = base64.b64encode(decrypted_data).decode()
                href = f'<a href="data:application/zip;base64,{b64}" download="decrypted_files.zip">{t["download_decrypted"]}</a>'
                st.markdown(href, unsafe_allow_html=True)
                st.success(t["success_decrypt"])

                with st.expander(t["show_files"]):
                    extract_zip_and_display(decrypted_data)

            except Exception as e:
                st.error(t["error"])

# ميزة تشفير مجلد كامل
st.markdown("---")
st.subheader(t["folder_encrypt"])
folder_path = st.text_input(t["folder_path"])

if st.button(t["folder_encrypt"]):
    if folder_path and os.path.isdir(folder_path):
        key = get_secret_key()
        zipped_data = zip_folder(folder_path)
        encrypted_data = encrypt_data(zipped_data, key)

        b64 = base64.b64encode(encrypted_data).decode()
        href = f'<a href="data:file/octet-stream;base64,{b64}" download="encrypted_folder.bin">{t["download_encrypted"]}</a>'
        st.markdown(href, unsafe_allow_html=True)
        st.success(t["success_encrypt"])
    else:
        st.error("❌ المسار غير صحيح أو المجلد غير موجود.")

# ميزة فك تشفير مجلد مشفر
st.markdown("---")
st.subheader(t["folder_decrypt"])

encrypted_folder_file = st.file_uploader("📂 اختر ملف المجلد المشفر (bin):", type=["bin"])
output_folder = st.text_input(t["output_folder"])

if st.button(t["folder_decrypt"]):
    if encrypted_folder_file and output_folder:
        key = get_secret_key()
        encrypted_content = encrypted_folder_file.read()

        try:
            decrypted_data = decrypt_data(encrypted_content, key)
            save_decrypted_folder(decrypted_data, output_folder)
            st.success(t["success_decrypt"] + f" ✅ تم استخراج الملفات إلى {output_folder}")
        except Exception as e:
            st.error(t["error"])
    else:
        st.warning("⚠️ يرجى تحديد الملف والمسار.")
