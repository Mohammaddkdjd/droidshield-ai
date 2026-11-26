import { useEffect, useRef, useState } from "react";
import { Beaker, Check, Eye, Lock, Trash, Upload } from "./Icons.jsx";
import { DEMOS } from "../demo.js";

export default function Uploader({ onFile, onDemo, disabled, phase, progress, source }) {
  const inputRef = useRef(null);
  const [drag, setDrag] = useState(false);
  const [elapsed, setElapsed] = useState(0);
  const [hint, setHint] = useState("");

  useEffect(() => {
    if (phase !== "analyzing") return;
    setElapsed(0);
    const t = setInterval(() => setElapsed((s) => s + 1), 1000);
    return () => clearInterval(t);
  }, [phase]);

  function pick(files) {
    const f = files?.[0];
    if (!f || disabled) return;
    if (!f.name.toLowerCase().endsWith(".apk")) {
      setHint("الملف المختار ليس بامتداد ‎.apk");
      return;
    }
    setHint("");
    onFile(f);
  }

  const busy = phase === "uploading" || phase === "analyzing";

  return (
    <section className="card upload-card">
      {busy ? (
        <Progress phase={phase} progress={progress} elapsed={elapsed} source={source} />
      ) : (
        <div
          className={`dropzone ${drag ? "drag" : ""}`}
          onClick={() => inputRef.current?.click()}
          onDragOver={(e) => { e.preventDefault(); setDrag(true); }}
          onDragLeave={() => setDrag(false)}
          onDrop={(e) => { e.preventDefault(); setDrag(false); pick(e.dataTransfer.files); }}
          role="button"
          tabIndex={0}
          onKeyDown={(e) => (e.key === "Enter" || e.key === " ") && inputRef.current?.click()}
        >
          <input
            ref={inputRef}
            type="file"
            accept=".apk,application/vnd.android.package-archive"
            hidden
            onChange={(e) => { pick(e.target.files); e.target.value = ""; }}
          />
          <span className="drop-icon"><Upload width={26} height={26} /></span>
          <p className="drop-title">اسحب ملف APK وأفلته هنا</p>
          <p className="muted">أو <span className="link">اختر ملفاً من جهازك</span></p>
          <span className="drop-meta"><span className="ltr">.apk</span> · حتى <bdi className="ltr">100 MB</bdi></span>
          {hint && <p className="hint-error">{hint}</p>}
        </div>
      )}

      <div className="upload-foot">
        <ul className="trust">
          <li><Eye width={16} height={16} /> تحليل ساكن، لا يُشغَّل التطبيق</li>
          <li><Trash width={16} height={16} /> يُحذف الملف فور انتهاء الفحص</li>
          <li><Lock width={16} height={16} /> يُحلَّل في عملية معزولة على خادمك</li>
        </ul>
        <div className="demos">
          <span className="muted small"><Beaker width={15} height={15} /> لا يوجد ملف؟ جرّب مثالاً:</span>
          {Object.entries(DEMOS).map(([k, d]) => (
            <button key={k} className="chip-btn" disabled={busy} onClick={() => onDemo(k)}>{d.title}</button>
          ))}
        </div>
      </div>
    </section>
  );
}

function Progress({ phase, progress, elapsed, source }) {
  const isDemo = source?.kind === "demo";
  const steps = [
    { key: "upload", label: isDemo ? "تجهيز الميزات" : "رفع الملف" },
    { key: "analyze", label: isDemo ? "حساب الاحتمال (SVM)" : "التحليل الساكن (12 وحدة)" },
    { key: "explain", label: isDemo ? "تفسير القرار (SHAP)" : "التنبؤ وتفسير القرار" },
  ];
  const activeIdx = phase === "uploading" ? 0 : 1;

  return (
    <div className="progress" aria-live="polite">
      <p className="progress-file">
        <span className="muted">جارٍ فحص</span> <span className="strong ltr">{source?.name}</span>
      </p>
      <ol className="steps">
        {steps.map((s, i) => {
          const state = i < activeIdx ? "done" : i === activeIdx || (activeIdx === 1 && i === 2) ? "active" : "todo";
          return (
            <li key={s.key} className={`step ${state}`}>
              <span className="step-dot">{state === "done" ? <Check width={14} height={14} /> : i + 1}</span>
              <span>{s.label}</span>
            </li>
          );
        })}
      </ol>
      {phase === "uploading" ? (
        <div className="bar"><div style={{ width: `${progress * 100}%` }} /></div>
      ) : (
        <div className="bar indeterminate"><div /></div>
      )}
      <p className="muted small">
        {phase === "uploading"
          ? `${Math.round(progress * 100)}%`
          : `مضى ${elapsed} ث · التطبيقات الكبيرة قد تحتاج دقيقة أو أكثر`}
      </p>
    </div>
  );
}
