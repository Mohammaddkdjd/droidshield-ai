# 🛡️ Android Malware XAI — كشف البرمجيات الخبيثة في أندرويد مع التفسير

موقع ويب يفحص ملفات **APK** ويحدد إن كانت خبيثة باستخدام **التحليل الساكن** و**التعلّم الآلي (SVM)**،
ثم يشرح سبب القرار باستخدام **SHAP** على شكل رسم Waterfall تفاعلي.

---

## ✨ المزايا
- رفع ملف APK من المتصفح والحصول على **نسبة أمان** فورية
- استخراج الميزات عبر **Androguard**: الصلاحيات، فلاتر النوايا، استدعاءات API الحساسة، الروابط المخفية وأوامر النظام
- تصنيف بواسطة **SVM مع RBF Kernel** واحتمالية مُعايَرة
- تفسير القرار عبر **SHAP KernelExplainer**: أي الميزات دفعت نحو "خبيث" وأيها نحو "سليم"
- (مرحلة متقدمة) **كشف التعمية**: إنتروبي النصوص ونسبة الأسماء ذات الحرف الواحد

## 🧱 خط المعالجة

```
APK ─► Androguard ─► [StandardScaler] ─► SVM (RBF) ─► SHAP ─► Gauge + Waterfall
```

| الطبقة | التقنية |
|---|---|
| الواجهة الأمامية | React (Vite) + Recharts/Plotly |
| الواجهة الخلفية | FastAPI (Python 3.11) |
| استخراج الميزات | Androguard 4.x |
| النموذج | scikit-learn `SVC(kernel="rbf", probability=True)` |
| التفسير | SHAP `KernelExplainer` |

## 📊 مجموعة البيانات
**Drebin-215**: 15,036 تطبيقاً (5,560 خبيث + 9,476 سليم) و215 ميزة ثنائية
(صلاحيات، API، Intents، أوامر نظام).
التحميل: [figshare — Android malware dataset for machine learning](https://figshare.com/articles/dataset/Android_malware_dataset_for_machine_learning_2/5854653)

ضع ملف CSV داخل مجلد `data/`.

> ⚠️ النموذج يعتمد على أذونات التطبيق فقط (110 إذناً من `Final_Balanced_Three_Datasets.csv`)؛ أذونات Android الحديثة غير الموجودة في البيانات لا تدخل في القرار.

## 📁 هيكل المشروع
```
android-malware-xai/
├── backend/
│   ├── droidshield_engine/       # محرك التحليل الثابت: APK ──► raw_analysis + متجه 110 ميزة
│   ├── ml/
│   │   ├── train_droidshield.py  # تدريب SVM على الـ 110 ميزة + خلفية SHAP + بطاقة النموذج
│   │   ├── clean_dataset.py      # حذف المكرر والمتعارض من الـ Dataset
│   │   └── explainer.py          # التنبؤ + تفسير SHAP + التحقق من بصمة الـ Schema
│   ├── models/droidshield/       # مخرجات التدريب (svm_rbf.joblib, model_card.json ...)
│   └── requirements.txt
├── frontend/                     # تطبيق React
├── data/                         # مجموعة البيانات (غير مرفوعة إلى Git)
├── PLAN.md                       # خطة العمل
└── README.md
```

## ⚡ التشغيل السريع

| الطريقة | ماذا تفعل |
|---|---|
| **VS Code ← F5** | يشغّل الخادم (مع التصحيح) + الواجهة ويفتح Chrome على الموقع ("▶ Run Full Stack") |
| **VS Code ← Ctrl+Shift+B** | يشغّل الخادم + الواجهة في طرفيتين ويفتح المتصفح الافتراضي |
| **PowerShell** | `powershell -ExecutionPolicy Bypass -File .\start.ps1` |

للإيقاف في VS Code: Shift+F5، أو Terminal ← Run Task ← **Stop Servers**.

## 🐳 التشغيل عبر Docker

```bash
# بناء الصور (مرة واحدة أو بعد تعديل الكود)
docker build -t android-malware-xai-backend ./backend
docker build -t android-malware-xai-frontend ./frontend

# التشغيل / الإيقاف
docker compose up -d
docker compose down
```

| الخدمة | العنوان |
|---|---|
| الموقع | http://localhost:8080 |
| الواجهة الخلفية (API) | http://localhost:8000/docs |

الواجهة تتصل بالخادم عبر Nginx على المسار `/api`.
> ملاحظة: نستخدم `docker build` بدلاً من `docker compose up --build` لأن Compose v5 على Windows يطلب صلاحية `--allow=fs.read` عند البناء.

## 🚀 التشغيل (خطوة بخطوة)

### 1) تثبيت المتطلبات
```bash
cd android-malware-xai
python -m venv .venv
.venv\Scripts\activate          # Windows
pip install -r backend/requirements.txt
```

### 2) تدريب النموذج
```bash
python backend/ml/train_droidshield.py
```
المخرجات في `backend/models/droidshield/`: `svm_rbf.joblib` ، `feature_names.json` ، `shap_background.npy` ، `metrics.json` ، `model_card.json` (فيه بصمة الـ Schema؛ الخادم لا يعمل إن لم تطابق المحرك)

### 3) تحليل ملف APK بالمحرك
```bash
cd backend
python -m droidshield_engine analyze path/to/app.apk      # ملف واحد
python -m droidshield_engine batch  path/to/apks_folder   # مجلد كامل
python -m droidshield_engine schema                       # عرض الـ Schema والتحقق منها
```

### 4) تشغيل الواجهة الخلفية (FastAPI)
```bash
cd backend
uvicorn app.main:app --port 8000
```
| النقطة | الوصف |
|---|---|
| `POST /predict` | رفع ملف APK (`multipart/form-data`، الحقل `file`) |
| `POST /predict/features` | إرسال الميزات مباشرة: `{"features": {"SEND_SMS": 1, ...}}` |
| `GET /model/info` | مقاييس النموذج |
| `GET /docs` | توثيق تفاعلي (Swagger) |

مثال على الاستجابة:
```json
{
  "label": "malware",
  "malware_probability": 0.9731,
  "confidence": 0.9731,
  "safety_score": 2.7,
  "threshold": 0.5,
  "active_features": 13,
  "explanation": {
    "base_value": 0.3488,
    "prediction": 0.9731,
    "top_features": [
      {"feature": "chmod", "category": "Commands signature", "value": 1.0, "shap": 0.1078, "direction": "malware"},
      {"feature": "SEND_SMS", "category": "Manifest Permission", "value": 1.0, "shap": 0.0769, "direction": "malware"}
    ],
    "other_features_shap": 0.0
  },
  "app_info": {"package": "...", "app_name": "...", "sha256": "...", "permissions": ["..."], "urls": ["..."]},
  "obfuscation": {"string_entropy_mean": 3.58, "single_char_method_ratio": 0.03, "...": "..."},
  "elapsed_ms": 6154
}
```

### 5) تشغيل الواجهة الأمامية (React)
```bash
cd frontend
npm install
npm run dev        # http://localhost:5173
```

## 📈 نتائج النموذج (بيانات الاختبار 20%)
بعد **إزالة التكرار** من Drebin-215 (7,253 متجهاً فريداً من 15,031):

| المقياس | القيمة |
|---|---|
| Accuracy | 0.976 |
| F1 (malware) | 0.949 |
| ROC-AUC | 0.995 |
| معدل الإنذار الكاذب FPR (سليم ⇐ خبيث) | 1.7% (19 من 1,108) |
| معدل التفويت FNR (خبيث ⇐ سليم) | 4.7% (16 من 343) |
| أفضل معاملات | `C=10, gamma='scale'` |

> ⚠️ بدون إزالة التكرار تظهر دقة 99.1%، لكنها مضخّمة: 65% من بيانات الاختبار كانت نسخاً مطابقة لبيانات التدريب.

## 🔐 ملاحظات أمنية
- التحليل **ساكن فقط**؛ لا يُنفَّذ أي ملف APK على الخادم.
- تُحذف الملفات المرفوعة فور انتهاء التحليل.
- لا تحمّل نماذج `joblib/pickle` من مصادر غير موثوقة، فقد تنفّذ كوداً عند التحميل.
- تعامل مع عينات البرمجيات الخبيثة داخل بيئة معزولة (VM) فقط.

## 📚 مراجع
- Arp et al., *DREBIN: Effective and Explainable Detection of Android Malware*, NDSS 2014
- Yerima & Sezer, *DroidFusion*, IEEE Trans. Cybernetics 2018 (Drebin-215)
- Lundberg & Lee, *A Unified Approach to Interpreting Model Predictions (SHAP)*, NeurIPS 2017
- [Androguard](https://github.com/androguard/androguard) · [SHAP](https://github.com/shap/shap) · [pralab/android-detectors](https://github.com/pralab/android-detectors)

## 📄 الترخيص
MIT
