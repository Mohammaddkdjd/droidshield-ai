export const API_URL = import.meta.env.VITE_API_URL || "http://localhost:8000";

/** يرفع ملف APK إلى POST /predict مع تتبّع تقدم الرفع. */
export function scanApk(file, { onUploadProgress, onUploaded } = {}) {
  return new Promise((resolve, reject) => {
    const xhr = new XMLHttpRequest();
    const form = new FormData();
    form.append("file", file);

    xhr.open("POST", `${API_URL}/predict`);
    xhr.responseType = "json";
    xhr.upload.onprogress = (e) => {
      if (e.lengthComputable) onUploadProgress?.(e.loaded / e.total);
    };
    xhr.upload.onload = () => onUploaded?.();
    xhr.onload = () => {
      if (xhr.status >= 200 && xhr.status < 300) resolve(xhr.response);
      else reject(new Error(xhr.response?.detail || `خطأ من الخادم (${xhr.status})`));
    };
    xhr.onerror = () => reject(new Error("تعذّر الاتصال بالخادم. تأكد من تشغيل الواجهة الخلفية على المنفذ 8000."));
    xhr.send(form);
  });
}

/** يرسل الميزات مباشرة إلى POST /predict/features. */
export async function scanFeatures(features) {
  let res;
  try {
    res = await fetch(`${API_URL}/predict/features`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ features }),
    });
  } catch {
    throw new Error("تعذّر الاتصال بالخادم. تأكد من تشغيل الواجهة الخلفية على المنفذ 8000.");
  }
  const data = await res.json().catch(() => ({}));
  if (!res.ok) throw new Error(data.detail || `خطأ من الخادم (${res.status})`);
  return data;
}

export async function getModelInfo() {
  const res = await fetch(`${API_URL}/model/info`);
  if (!res.ok) throw new Error("model info unavailable");
  return res.json();
}
