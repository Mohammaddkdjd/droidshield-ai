import { CheckCircle, Alert, Octagon, Download, Refresh } from "./Icons.jsx";

export const levelOf = (score) =>
  score >= 70
    ? { key: "good", Icon: CheckCircle, title: "آمن على الأرجح", desc: "لم يجد النموذج مؤشرات كافية على سلوك خبيث في أذونات التطبيق." }
    : score >= 40
    ? { key: "warning", Icon: Alert, title: "مشبوه، تحقّق قبل التثبيت", desc: "يحمل التطبيق بعض المؤشرات المرتبطة بالبرمجيات الخبيثة." }
    : { key: "critical", Icon: Octagon, title: "خبيث على الأرجح", desc: "يطابق التطبيق أنماطاً قوية من البرمجيات الخبيثة. لا يُنصح بتثبيته." };

const mb = (b) => `${(b / 1024 / 1024).toFixed(1)} MB`;

export default function VerdictBanner({ result, source, onReset }) {
  const lv = levelOf(result.safety_score);
  const info = result.app_info;

  function downloadReport() {
    const blob = new Blob([JSON.stringify({ source, ...result }, null, 2)], { type: "application/json" });
    const a = document.createElement("a");
    a.href = URL.createObjectURL(blob);
    a.download = `droidshield-report-${info?.package || "features"}.json`;
    a.click();
    URL.revokeObjectURL(a.href);
  }

  const meta = info
    ? [
        info.version && { k: "الإصدار", v: info.version },
        info.size_bytes && { k: "الحجم", v: mb(info.size_bytes) },
        info.target_sdk && { k: "Target SDK", v: info.target_sdk },
        { k: "الأذونات", v: info.permissions?.length ?? 0 },
      ].filter(Boolean)
    : [];

  return (
    <section className={`card verdict v-${lv.key}`} id="verdict">
      <div className="verdict-main">
        <span className="verdict-icon"><lv.Icon width={32} height={32} /></span>
        <div className="verdict-body">
          <p className="verdict-kicker">نتيجة الفحص</p>
          <h2 className="verdict-title">{lv.title}</h2>
          <p className="verdict-desc">{lv.desc}</p>
        </div>
        <div className="verdict-actions">
          <button className="btn" onClick={downloadReport}><Download width={17} height={17} /> تنزيل التقرير</button>
          <button className="btn btn-primary" onClick={onReset}><Refresh width={17} height={17} /> فحص ملف آخر</button>
        </div>
      </div>
      <div className="verdict-target">
        {info ? (
          <>
            <div className="app-id">
              <span className="app-name">{info.app_name || info.file_name}</span>
              <span className="ltr mono muted">{info.package}</span>
            </div>
            <dl className="meta-chips">
              {meta.map((m) => (
                <div key={m.k}><dt>{m.k}</dt><dd className="ltr">{m.v}</dd></div>
              ))}
            </dl>
          </>
        ) : (
          <span className="muted">مثال تجريبي: {source?.name}</span>
        )}
      </div>
    </section>
  );
}
