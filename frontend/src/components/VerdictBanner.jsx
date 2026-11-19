import { CheckCircle, Alert, Octagon, Download, Refresh } from "./Icons.jsx";

export const levelOf = (score) =>
  score >= 70
    ? { key: "good", Icon: CheckCircle, title: "آمن على الأرجح", desc: "لم يجد النموذج مؤشرات كافية على سلوك خبيث." }
    : score >= 40
    ? { key: "warning", Icon: Alert, title: "مشبوه، تحقّق قبل التثبيت", desc: "يحمل التطبيق بعض المؤشرات المرتبطة بالبرمجيات الخبيثة." }
    : { key: "critical", Icon: Octagon, title: "خبيث على الأرجح", desc: "يطابق التطبيق أنماطاً قوية من البرمجيات الخبيثة. لا يُنصح بتثبيته." };

export default function VerdictBanner({ result, source, onReset }) {
  const lv = levelOf(result.safety_score);
  const info = result.app_info;

  function downloadReport() {
    const blob = new Blob([JSON.stringify({ source, ...result }, null, 2)], { type: "application/json" });
    const a = document.createElement("a");
    a.href = URL.createObjectURL(blob);
    a.download = `scan-report-${info?.package || "features"}.json`;
    a.click();
    URL.revokeObjectURL(a.href);
  }

  return (
    <section className={`card verdict v-${lv.key}`}>
      <span className="verdict-icon"><lv.Icon width={30} height={30} /></span>
      <div className="verdict-body">
        <p className="verdict-kicker">نتيجة الفحص</p>
        <h2 className="verdict-title">{lv.title}</h2>
        <p className="muted">{lv.desc}</p>
        <p className="verdict-target">
          {info ? (
            <>
              <span className="strong">{info.app_name || info.file_name}</span>
              <span className="ltr mono muted">{info.package}</span>
            </>
          ) : (
            <span className="muted">مثال تجريبي: {source?.name}</span>
          )}
        </p>
      </div>
      <div className="verdict-actions">
        <button className="btn" onClick={downloadReport}><Download width={17} height={17} /> تنزيل التقرير</button>
        <button className="btn btn-primary" onClick={onReset}><Refresh width={17} height={17} /> فحص ملف آخر</button>
      </div>
    </section>
  );
}
