import { Code, Cpu, Layers, Sparkle, Upload } from "./Icons.jsx";

const pct = (v) => (v == null ? "—" : `${(v * 100).toFixed(1)}%`);

/** شريط أرقام النموذج: كلها من GET /model/info، لا أرقام مكتوبة يدوياً. */
export function StatsStrip({ info }) {
  const stats = [
    { value: pct(info?.accuracy), label: "دقة النموذج على بيانات الاختبار" },
    { value: info?.roc_auc != null ? info.roc_auc.toFixed(3) : "—", label: "ROC-AUC" },
    { value: info?.n_features ?? "—", label: "إذناً يراقبها النموذج" },
    { value: "12", label: "وحدة تحليل ساكن في المحرك" },
  ];
  return (
    <section className="stats-strip" aria-label="أرقام النموذج">
      {stats.map((s) => (
        <div key={s.label} className="stat">
          <span className="stat-value ltr">{s.value}</span>
          <span className="stat-label">{s.label}</span>
        </div>
      ))}
    </section>
  );
}

const STEPS = [
  { Icon: Upload, title: "رفع آمن", text: "يُفحص الملف قبل أي تحليل: بنية ZIP، والحماية من Zip Bomb والمسارات الخطرة." },
  { Icon: Layers, title: "تحليل ساكن شامل", text: "12 وحدة تستخرج الأذونات والمكوّنات والكود والشبكة والشهادات دون تشغيل التطبيق." },
  { Icon: Cpu, title: "تصنيف بالتعلّم الآلي", text: "نموذج SVM معايَر يحسب احتمال الخبث من متجه أذونات بنفس ترتيب بيانات التدريب." },
  { Icon: Sparkle, title: "تفسير القرار", text: "قيم SHAP تبيّن أي الأذونات دفعت القرار نحو «خبيث» وأيها نحو «سليم»." },
];

export function HowItWorks() {
  return (
    <section className="how" aria-labelledby="how-title">
      <div className="section-head">
        <p className="kicker"><Code width={14} height={14} /> كيف يعمل</p>
        <h2 id="how-title">من ملف APK إلى قرار قابل للتفسير</h2>
      </div>
      <ol className="how-grid">
        {STEPS.map(({ Icon, title, text }, i) => (
          <li key={title} className="how-step">
            <span className="how-num ltr">{String(i + 1).padStart(2, "0")}</span>
            <span className="how-icon"><Icon width={22} height={22} /></span>
            <h3>{title}</h3>
            <p>{text}</p>
          </li>
        ))}
      </ol>
    </section>
  );
}
