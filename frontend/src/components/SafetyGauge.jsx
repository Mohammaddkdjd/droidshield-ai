import { levelOf } from "./VerdictBanner.jsx";

// عداد الأمان: قوس من 0 إلى 100 مع علامات للحدود 40 و70. اللون حالة ويرافقه دائماً نص.
export default function SafetyGauge({ result }) {
  const score = result.safety_score;
  const lv = levelOf(score);
  const r = 80, cx = 100, cy = 100;
  const len = Math.PI * r;
  const filled = (score / 100) * len;
  const tick = (pct) => {
    const a = Math.PI * (1 - pct / 100);
    return {
      x1: cx + (r - 14) * Math.cos(a), y1: cy - (r - 14) * Math.sin(a),
      x2: cx + (r + 14) * Math.cos(a), y2: cy - (r + 14) * Math.sin(a),
      tx: cx + (r + 24) * Math.cos(a), ty: cy - (r + 24) * Math.sin(a),
    };
  };

  return (
    <section className="card gauge-card">
      <div className="card-title">
        <h3>نسبة الأمان</h3>
        <span className="muted small">100 = آمن تماماً</span>
      </div>
      <svg viewBox="-10 -10 220 125" className="gauge" role="img"
           aria-label={`نسبة الأمان ${Math.round(score)} من 100: ${lv.title}`}>
        <path d="M20 100 A80 80 0 0 1 180 100" className="gauge-track" />
        <path d="M20 100 A80 80 0 0 1 180 100" className={`gauge-fill s-${lv.key}`}
              strokeDasharray={`${filled} ${len}`} />
        {[40, 70].map((p) => {
          const t = tick(p);
          return (
            <g key={p}>
              <line x1={t.x1} y1={t.y1} x2={t.x2} y2={t.y2} className="gauge-tick" />
              <text x={t.tx} y={t.ty} textAnchor="middle" className="gauge-tick-label">{p}</text>
            </g>
          );
        })}
        <text x="100" y="86" textAnchor="middle" className="gauge-value">{Math.round(score)}</text>
        <text x="100" y="106" textAnchor="middle" className="gauge-unit">من 100</text>
      </svg>
      <div className="gauge-scale" aria-hidden>
        <span><i className="sw s-critical-bg" /> خبيث &lt; 40</span>
        <span><i className="sw s-warning-bg" /> مشبوه</span>
        <span><i className="sw s-good-bg" /> آمن ≥ 70</span>
      </div>
    </section>
  );
}
