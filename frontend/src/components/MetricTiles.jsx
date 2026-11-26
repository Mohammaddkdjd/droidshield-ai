import { Clock, Gauge, Layers, Sparkle } from "./Icons.jsx";

// الأرقام داخل نص عربي تُعزل بـ <bdi> حتى لا تنتقل علامة % إلى الجهة الخطأ
const Num = ({ children }) => <bdi className="ltr">{children}</bdi>;

export default function MetricTiles({ result }) {
  const pct = (v) => `${(v * 100).toFixed(1)}%`;
  const tiles = [
    {
      Icon: Gauge,
      label: "احتمال الخبث",
      value: pct(result.malware_probability),
      sub: <>عتبة القرار <Num>{pct(result.threshold)}</Num></>,
      tone: result.label === "malware" ? "critical" : "neutral",
    },
    {
      Icon: Sparkle,
      label: "ثقة النموذج",
      value: pct(result.confidence),
      sub: `في تصنيف «${result.label === "malware" ? "خبيث" : "سليم"}»`,
    },
    {
      Icon: Layers,
      label: "الأذونات المكتشفة",
      value: `${result.active_features}`,
      sub: <>من أصل <Num>{result.total_features}</Num> إذناً يراقبها النموذج</>,
    },
    {
      Icon: Clock,
      label: "زمن الفحص",
      value: result.elapsed_ms >= 1000 ? `${(result.elapsed_ms / 1000).toFixed(1)} ث` : `${result.elapsed_ms} مث`,
      sub: result.cached ? "من الذاكرة المؤقتة (فُحص سابقاً)" : "تحليل + تنبؤ + تفسير",
    },
  ];

  return (
    <section className="tiles">
      {tiles.map(({ Icon, ...t }) => (
        <div key={t.label} className={`card tile tone-${t.tone || "neutral"}`}>
          <span className="tile-head">
            <span className="tile-icon"><Icon width={17} height={17} /></span>
            <span className="tile-label">{t.label}</span>
          </span>
          <span className="tile-value"><Num>{t.value}</Num></span>
          <span className="tile-sub">{t.sub}</span>
        </div>
      ))}
    </section>
  );
}
