import { Cpu, Github, Shield } from "./Icons.jsx";

const REPO_URL = "https://github.com/Mohammaddkdjd/droidshield-ai";

export default function ModelCard({ info }) {
  const pct = (v) => (v == null ? "—" : `${(v * 100).toFixed(1)}%`);
  const stats = info
    ? [
        { label: "الدقة", value: pct(info.accuracy) },
        { label: "F1 (خبيث)", value: info.f1?.toFixed(3) },
        { label: "ROC-AUC", value: info.roc_auc?.toFixed(3) },
        { label: "إنذار كاذب", value: pct(info.false_positive_rate) },
        { label: "خبيث فائت", value: pct(info.false_negative_rate) },
      ]
    : [];

  return (
    <footer className="site-footer">
      <section className="model-card">
        <div className="model-head">
          <span className="model-icon"><Cpu width={18} height={18} /></span>
          <div>
            <span className="strong">عن النموذج</span>
            <span className="muted small model-sub">
              {info ? `SVM (RBF) معايَر · ${info.dataset} · ${info.n_features} إذناً` : "غير متصل بالخادم"}
            </span>
          </div>
        </div>
        {info && (
          <dl className="model-stats">
            {stats.map((s) => (
              <div key={s.label}><dt>{s.label}</dt><dd className="ltr">{s.value}</dd></div>
            ))}
          </dl>
        )}
        <p className="muted small disclaimer">
          النتيجة تقدير إحصائي من تحليل ساكن، وليست حكماً قاطعاً. يعتمد النموذج على أذونات التطبيق فقط،
          وأذونات Android الحديثة غير الموجودة في بيانات التدريب لا تدخل في القرار.
        </p>
      </section>
      <div className="footer-bar">
        <span className="footer-brand"><Shield width={16} height={16} /> <span className="ltr">DroidShield AI</span> · مشروع تخرج</span>
        <span className="muted small">تحليل ساكن · تعلّم آلي · ذكاء اصطناعي قابل للتفسير (SHAP)</span>
        <a href={REPO_URL} target="_blank" rel="noreferrer" className="footer-link">
          <Github width={16} height={16} /> الكود المصدري
        </a>
      </div>
    </footer>
  );
}
