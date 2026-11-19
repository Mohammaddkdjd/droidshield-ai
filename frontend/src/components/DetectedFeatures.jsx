import { useState } from "react";

export const CATEGORY_AR = {
  "Manifest Permission": "الصلاحيات",
  "API call signature": "استدعاءات API",
  Intent: "فلاتر النوايا (Intents)",
  "Commands signature": "أوامر النظام",
  Unknown: "أخرى",
};
const ORDER = ["Manifest Permission", "API call signature", "Intent", "Commands signature", "Unknown"];

export default function DetectedFeatures({ result }) {
  const list = result.detected_features || [];
  const shapByFeature = Object.fromEntries(
    (result.explanation?.top_features || []).map((f) => [f.feature, f.shap])
  );
  const groups = ORDER
    .map((c) => ({ c, items: list.filter((f) => (f.category || "Unknown") === c) }))
    .filter((g) => g.items.length);
  const [open, setOpen] = useState(
    () => [...groups].sort((a, b) => b.items.length - a.items.length)[0]?.c
  );
  const max = Math.max(1, ...groups.map((g) => g.items.length));

  return (
    <section className="card">
      <div className="card-title">
        <h3>الميزات المكتشفة في التطبيق</h3>
        <span className="muted small">{list.length} ميزة</span>
      </div>

      {groups.length === 0 ? (
        <p className="muted">لم تُكتشف أي ميزة من الميزات التي يراقبها النموذج.</p>
      ) : (
        <>
          <div className="cat-bars" role="tablist">
            {groups.map((g) => (
              <button key={g.c} role="tab" aria-selected={open === g.c}
                      className={`cat-row ${open === g.c ? "active" : ""}`} onClick={() => setOpen(g.c)}>
                <span className="cat-name">{CATEGORY_AR[g.c] || g.c}</span>
                <span className="cat-track"><span style={{ width: `${(g.items.length / max) * 100}%` }} /></span>
                <span className="cat-count">{g.items.length}</span>
              </button>
            ))}
          </div>
          <div className="chips" role="tabpanel">
            {groups.find((g) => g.c === open)?.items.map((f) => {
              const s = shapByFeature[f.feature];
              const cls = s > 0 ? "chip-mal" : s < 0 ? "chip-ben" : "";
              return (
                <span key={f.feature} className={`chip ltr ${cls}`}
                      title={s != null ? `مساهمة SHAP: ${(s * 100).toFixed(1)}` : "تأثير ضعيف"}>
                  {s > 0 && <span aria-label="يدفع نحو خبيث">▲ </span>}
                  {s < 0 && <span aria-label="يدفع نحو سليم">▼ </span>}
                  {f.feature}
                </span>
              );
            })}
          </div>
          <p className="muted small legend-note">
            <span className="chip chip-mal mini">▲</span> من أكثر الميزات دفعاً نحو «خبيث» ·{" "}
            <span className="chip chip-ben mini">▼</span> نحو «سليم»
          </p>
        </>
      )}
    </section>
  );
}
