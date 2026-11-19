import { useEffect, useMemo, useRef, useState } from "react";
import { Chart, Table } from "./Icons.jsx";

const CATEGORY_AR = {
  "Manifest Permission": "صلاحية",
  "API call signature": "استدعاء API",
  Intent: "نيّة (Intent)",
  "Commands signature": "أمر نظام",
};

const fmt = (v) => `${v > 0 ? "+" : v < 0 ? "−" : ""}${Math.abs(v * 100).toFixed(1)}`;

/**
 * رسم Waterfall لقيم SHAP: يبدأ من القيمة الأساسية (متوسط احتمال الخبث)،
 * وكل ميزة تزيح الاحتمال نحو "خبيث" (أحمر) أو "سليم" (أزرق)، حتى التنبؤ النهائي.
 * المحور = احتمال الخبث بالنسبة المئوية.
 */
export default function ShapWaterfall({ explanation }) {
  const [hover, setHover] = useState(null);
  const [showTable, setShowTable] = useState(false);
  const wrapRef = useRef(null);
  const [boxW, setBoxW] = useState(0);

  useEffect(() => {
    const el = wrapRef.current;
    if (!el) return;
    const ro = new ResizeObserver(([e]) => setBoxW(e.contentRect.width));
    ro.observe(el);
    return () => ro.disconnect();
  }, [showTable]);

  const rows = useMemo(() => {
    let cum = explanation.base_value;
    const out = [];
    const items = [...explanation.top_features];
    if (Math.abs(explanation.other_features_shap) > 1e-4) {
      items.push({ feature: "ميزات أخرى", category: null, value: null, shap: explanation.other_features_shap, other: true });
    }
    for (const f of items) {
      out.push({ ...f, start: cum, end: cum + f.shap });
      cum += f.shap;
    }
    return out;
  }, [explanation]);

  const final = explanation.prediction;
  const pts = [explanation.base_value, final, ...rows.flatMap((r) => [r.start, r.end])];
  const lo = Math.max(0, Math.min(...pts) - 0.05);
  const hi = Math.min(1, Math.max(...pts) + 0.05);

  // عرض الرسم = عرض الحاوية الفعلي (viewBox بالبكسل) فيبقى حجم الخط ثابتاً على الجوال والحاسوب
  const W = Math.max(300, Math.round(boxW || 720));
  const compact = W < 560;
  const labelW = compact ? Math.round(W * 0.44) : 250;
  const valueW = compact ? 44 : 60;
  const rowH = compact ? 26 : 32, top = 30;
  const maxChars = Math.floor((labelW - 18) / (compact ? 7.3 : 8.2));
  const plotW = W - labelW - valueW - 14; // مسافة بين الرسم وعمود القيم
  const x = (v) => labelW + ((v - lo) / (hi - lo)) * plotW;
  const H = top + rowH * (rows.length + 2) + 10;
  const ticks = Array.from({ length: 5 }, (_, i) => lo + ((hi - lo) * i) / 4);

  return (
    <section className="card">
      <div className="card-head">
        <div>
          <p className="kicker">تفسير القرار · SHAP</p>
          <h3>لماذا اتخذ النموذج هذا القرار؟</h3>
          <p className="muted small">
            يبدأ الرسم من متوسط احتمال الخبث في بيانات التدريب (<bdi className="ltr">{(explanation.base_value * 100).toFixed(1)}%</bdi>)،
            ثم تضيف كل ميزة إليه أو تطرح منه حتى يصل إلى احتمال هذا التطبيق (<bdi className="ltr">{(final * 100).toFixed(1)}%</bdi>).
            القيم بالنقاط المئوية.
          </p>
        </div>
        <div className="seg" role="tablist" aria-label="طريقة العرض">
          <button role="tab" aria-selected={!showTable} className={!showTable ? "on" : ""} onClick={() => setShowTable(false)}>
            <Chart width={16} height={16} /> رسم
          </button>
          <button role="tab" aria-selected={showTable} className={showTable ? "on" : ""} onClick={() => setShowTable(true)}>
            <Table width={16} height={16} /> جدول
          </button>
        </div>
      </div>

      <div className="legend">
        <span><i className="sw sw-mal" /> يدفع نحو «خبيث»</span>
        <span><i className="sw sw-ben" /> يدفع نحو «سليم»</span>
        <span className="muted">✕ ميزة غائبة عن التطبيق (غيابها أثّر في القرار)</span>
      </div>

      {showTable ? (
        <table className="shap-table">
          <thead>
            <tr><th>الميزة</th><th>النوع</th><th>الحالة</th><th>المساهمة (نقاط مئوية)</th></tr>
          </thead>
          <tbody>
            {rows.map((r) => (
              <tr key={r.feature}>
                <td className="ltr">{r.feature}</td>
                <td>{r.category ? CATEGORY_AR[r.category] || r.category : "—"}</td>
                <td>{r.value == null ? "—" : r.value ? "موجودة" : "غائبة"}</td>
                <td className="ltr">{fmt(r.shap)}</td>
              </tr>
            ))}
          </tbody>
        </table>
      ) : (
        <div className="waterfall-wrap" dir="ltr" ref={wrapRef}>
          <svg viewBox={`0 0 ${W} ${H}`} className="waterfall" role="img"
               aria-label="رسم Waterfall لمساهمات الميزات في القرار">
            {ticks.map((t) => (
              <g key={t}>
                <line x1={x(t)} x2={x(t)} y1={top - 6} y2={H - 10} className="grid" />
                <text x={x(t)} y={top - 12} textAnchor="middle" className="tick">{Math.round(t * 100)}%</text>
              </g>
            ))}

            <Row rowH={rowH} y={top} label={compact ? "نقطة البداية" : "متوسط النموذج (نقطة البداية)"} x={x} labelW={labelW} marker={explanation.base_value}
                 valueText={`${(explanation.base_value * 100).toFixed(1)}%`} W={W} />

            {rows.map((r, i) => {
              const y = top + rowH * (i + 1);
              const x0 = x(Math.min(r.start, r.end));
              const w = Math.max(2, Math.abs(x(r.end) - x(r.start)));
              const isMal = r.shap > 0;
              return (
                <g key={r.feature}
                   onMouseEnter={() => setHover({ ...r, y })}
                   onMouseLeave={() => setHover(null)}
                   className="wf-row">
                  <rect x={0} y={y} width={W} height={rowH} className="hit" />
                  <text x={labelW - 10} y={y + rowH / 2 + 4} textAnchor="end" className={`wf-label ${r.other ? "muted-ink" : ""}`}>
                    {r.value === 0 ? "✕ " : ""}{truncate(r.feature, maxChars - (r.value === 0 ? 2 : 0))}
                  </text>
                  <rect x={x0} y={y + 6} width={w} height={rowH - 12} rx={3}
                        className={isMal ? "bar-mal" : "bar-ben"} />
                  {i < rows.length - 1 && (
                    <line x1={x(r.end)} x2={x(r.end)} y1={y + rowH - 6} y2={y + rowH + 6} className="connector" />
                  )}
                  <text x={W - 4} y={y + rowH / 2 + 4} textAnchor="end" className="wf-value">{fmt(r.shap)}</text>
                </g>
              );
            })}

            <Row rowH={rowH} y={top + rowH * (rows.length + 1)} label={compact ? "النتيجة" : "احتمال هذا التطبيق"} x={x} labelW={labelW}
                 marker={final} valueText={`${(final * 100).toFixed(1)}%`} W={W} strong />
          </svg>

          {hover && (
            <div className="tooltip" style={{ top: `${(hover.y / H) * 100}%` }} dir="rtl">
              <div className="ltr strong">{hover.feature}</div>
              {hover.category && <div>{CATEGORY_AR[hover.category] || hover.category} · {hover.value ? "موجودة في التطبيق" : "غير موجودة في التطبيق"}</div>}
              <div>المساهمة: <b className="ltr">{fmt(hover.shap)}</b> نقطة نحو «{hover.shap > 0 ? "خبيث" : "سليم"}»</div>
              <div className="muted">الاحتمال: <bdi className="ltr">{(hover.start * 100).toFixed(1)}% → {(hover.end * 100).toFixed(1)}%</bdi></div>
            </div>
          )}
        </div>
      )}
    </section>
  );
}

function Row({ y, label, x, labelW, marker, valueText, W, strong, rowH }) {
  return (
    <g>
      <text x={labelW - 10} y={y + rowH / 2 + 4} textAnchor="end" className={`wf-label ${strong ? "strong-ink" : "muted-ink"}`}>{label}</text>
      <line x1={x(marker)} x2={x(marker)} y1={y + 3} y2={y + rowH - 3} className="marker" />
      <circle cx={x(marker)} cy={y + rowH / 2} r={4} className="marker-dot" />
      <text x={W - 4} y={y + rowH / 2 + 4} textAnchor="end" className={`wf-value ${strong ? "strong-ink" : ""}`}>{valueText}</text>
    </g>
  );
}

function truncate(s, n) {
  return s.length > n ? s.slice(0, n - 1) + "…" : s;
}
