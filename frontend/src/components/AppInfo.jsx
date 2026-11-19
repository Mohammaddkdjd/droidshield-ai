import { Package } from "./Icons.jsx";

const DANGEROUS = new Set([
  "SEND_SMS", "RECEIVE_SMS", "READ_SMS", "WRITE_SMS", "READ_CONTACTS", "READ_CALL_LOG",
  "CALL_PHONE", "PROCESS_OUTGOING_CALLS", "RECORD_AUDIO", "CAMERA", "ACCESS_FINE_LOCATION",
  "READ_PHONE_STATE", "INSTALL_PACKAGES", "SYSTEM_ALERT_WINDOW", "BIND_DEVICE_ADMIN",
  "BIND_ACCESSIBILITY_SERVICE", "WRITE_SETTINGS", "REQUEST_INSTALL_PACKAGES",
]);

const OBF = [
  { k: "string_entropy_mean", label: "متوسط إنتروبي النصوص", max: 8, fmt: (v) => v.toFixed(2) },
  { k: "high_entropy_string_ratio", label: "نصوص عالية الإنتروبي", max: 1, fmt: (v) => `${(v * 100).toFixed(1)}%` },
  { k: "single_char_class_ratio", label: "أسماء أصناف بحرف واحد", max: 1, fmt: (v) => `${(v * 100).toFixed(1)}%` },
  { k: "single_char_method_ratio", label: "أسماء دوال بحرف واحد", max: 1, fmt: (v) => `${(v * 100).toFixed(1)}%` },
];

export default function AppInfo({ result }) {
  const info = result.app_info;

  if (!info) {
    return (
      <section className="card empty-card">
        <Package width={28} height={28} className="muted" />
        <h3>معلومات التطبيق</h3>
        <p className="muted">تظهر بيانات الحزمة والصلاحيات ومؤشرات التعمية عند فحص ملف APK حقيقي.</p>
      </section>
    );
  }

  const perms = info.permissions.map((p) => p.split(".").pop());
  const dangerous = perms.filter((p) => DANGEROUS.has(p));

  return (
    <section className="card">
      <div className="card-title">
        <h3>معلومات التطبيق</h3>
        {info.version && <span className="badge ltr">v{info.version}</span>}
      </div>
      <dl className="kv">
        <div><dt>الاسم</dt><dd>{info.app_name || "—"}</dd></div>
        <div><dt>الحزمة</dt><dd className="ltr mono">{info.package}</dd></div>
        <div><dt>الحجم</dt><dd><bdi className="ltr">{(info.size_bytes / 1024 / 1024).toFixed(1)} MB</bdi></dd></div>
        <div><dt>SHA-256</dt><dd className="ltr mono" title={info.sha256}>{info.sha256.slice(0, 20)}…</dd></div>
      </dl>

      <h4>
        الصلاحيات <span className="muted">({perms.length})</span>
        {dangerous.length > 0 && <span className="badge badge-critical">{dangerous.length} خطرة</span>}
      </h4>
      <div className="chips">
        {[...perms].sort((a, b) => DANGEROUS.has(b) - DANGEROUS.has(a)).map((p) => (
          <span key={p} className={`chip ltr ${DANGEROUS.has(p) ? "chip-danger" : ""}`}>
            {DANGEROUS.has(p) && <span aria-label="خطرة">⚠ </span>}{p}
          </span>
        ))}
      </div>

      {result.obfuscation && (
        <>
          <h4>مؤشرات التعمية <span className="badge">تجريبي</span></h4>
          <div className="obf">
            {OBF.map((o) => {
              const v = result.obfuscation[o.k] ?? 0;
              return (
                <div key={o.k} className="obf-row">
                  <span className="obf-label">{o.label}</span>
                  <span className="obf-track"><span style={{ width: `${Math.min(1, v / o.max) * 100}%` }} /></span>
                  <span className="obf-value ltr">{o.fmt(v)}</span>
                </div>
              );
            })}
          </div>
          <p className="muted small">لا تدخل في قرار النموذج حالياً. نسبة عالية قد تعني تعمية أو ضغط الكود بأداة R8.</p>
        </>
      )}

      {info.urls?.length > 0 && (
        <details className="urls-box">
          <summary>الروابط المكتشفة في الكود ({info.urls.length})</summary>
          <ul className="urls ltr">{info.urls.map((u) => <li key={u}>{u}</li>)}</ul>
        </details>
      )}
    </section>
  );
}
