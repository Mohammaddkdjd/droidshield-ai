// الأرقام داخل نص عربي تُعزل بـ <bdi> حتى لا تنتقل علامة % إلى الجهة الخطأ
const Num = ({ children }) => <bdi className="ltr">{children}</bdi>;

export default function MetricTiles({ result }) {
  const pct = (v) => `${(v * 100).toFixed(1)}%`;
  const tiles = [
    {
      label: "احتمال الخبث",
      value: pct(result.malware_probability),
      sub: <>عتبة القرار <Num>{pct(result.threshold)}</Num></>,
    },
    {
      label: "ثقة النموذج",
      value: pct(result.confidence),
      sub: `في تصنيف «${result.label === "malware" ? "خبيث" : "سليم"}»`,
    },
    {
      label: "الميزات المكتشفة",
      value: `${result.active_features}`,
      sub: <>من أصل <Num>{result.total_features ?? 215}</Num> ميزة يراقبها النموذج</>,
    },
    {
      label: "زمن الفحص",
      value: result.elapsed_ms >= 1000 ? `${(result.elapsed_ms / 1000).toFixed(1)} ث` : `${result.elapsed_ms} مث`,
      sub: result.cached ? "من الذاكرة المؤقتة (فُحص سابقاً)" : "تحليل + تنبؤ + تفسير",
    },
  ];

  return (
    <section className="tiles">
      {tiles.map((t) => (
        <div key={t.label} className="card tile">
          <span className="tile-label">{t.label}</span>
          <span className="tile-value"><Num>{t.value}</Num></span>
          <span className="tile-sub">{t.sub}</span>
        </div>
      ))}
    </section>
  );
}
