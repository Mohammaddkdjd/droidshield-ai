import { Cpu } from "./Icons.jsx";

export default function ModelCard({ info }) {
  const pct = (v) => (v == null ? "—" : `${(v * 100).toFixed(1)}%`);
  const stats = info
    ? [
        { label: "الدقة", value: pct(info.accuracy) },
        { label: "F1", value: info.f1?.toFixed(3) },
        { label: "ROC-AUC", value: info.roc_auc?.toFixed(3) },
        { label: "إنذار كاذب", value: pct(info.false_positive_rate) },
        { label: "خبيث فائت", value: pct(info.false_negative_rate) },
      ]
    : [];

  return (
    <footer className="model-card">
      <div className="model-head">
        <Cpu width={18} height={18} />
        <span className="strong">عن النموذج</span>
        <span className="muted small">
          {info ? `SVM (RBF) معايَر · ${info.dataset} · ${info.n_features} ميزة` : "غير متصل"}
        </span>
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
    </footer>
  );
}
