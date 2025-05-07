# StreamlitEncrypt-Decrypt-App
## professional, full Streamlit app code — supporting encryption and decryption of any file or folder with Arabic (RTL) layout and button-based action.

It uses strong AES-256 encryption with a fixed secret key.

## يدعم جميع أنواع الملفات (وثائق، صور، فيديو، صوت، مجلدات).

🔒 زر تشفير يحول الملفات إلى ملف مشفر (encrypted_file.bin).

🔓 زر فك تشفير يعيدها إلى مجلد مضغوط (decrypted_files.zip).

الواجهة باللغة العربية وبـ الاتجاه من اليمين لليسار (RTL).

يستخدم AES-256 لتأمين الملفات بدون الحاجة لكلمة مرور من المستخدم (يستخدم مفتاح مخزن بالكود).
##  مميزات إضافية مدمجة:
يدعم رفع ملفات متعددة أو مجلد كامل (يتم ضغطه تلقائيًا).

آمن: يعالج كل شيء في الذاكرة (لا يتم حفظ الملفات على القرص).

رابط تحميل مباشر للملفات بعد التشفير أو فك التشفير.

ملاحظة 👇🏽
الملفات المشفرة تأخذ الامتداد .bin، والملفات المفكوكة ترجع في ملف ZIP يحتوي على الملفات الأصلية.
# To Run it
### pip install streamlit cryptography
## or
## pip install -r requirements.txt
### streamlit run app.py
