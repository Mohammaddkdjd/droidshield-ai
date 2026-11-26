import { Code, Fingerprint, Globe, Key, Layers, Server, Terminal, Unlock } from "./Icons.jsx";

const API_AR = {
  sms: "الرسائل SMS", phone: "الهاتف والمكالمات", contacts: "جهات الاتصال والحسابات", location: "الموقع",
  camera: "الكاميرا", microphone: "الميكروفون", network: "الشبكة", file_system: "نظام الملفات",
  reflection: "الانعكاس (Reflection)", dynamic_code_loading: "تحميل كود ديناميكي", cryptography: "التشفير",
  process_execution: "تنفيذ أوامر النظام", device_admin: "إدارة الجهاز", accessibility: "إمكانية الوصول",
  package_management: "إدارة التطبيقات", screen_capture: "تصوير الشاشة", overlay: "النوافذ الفوقية",
  clipboard: "الحافظة",
};
// فئات تستحق التنبيه البصري لأنها شائعة في البرمجيات الخبيثة (وليست دليلاً بحد ذاتها)
const SENSITIVE = new Set(["sms", "dynamic_code_loading", "process_execution", "device_admin", "accessibility",
                           "screen_capture", "overlay"]);
const COMPONENT_AR = { activities: "نشاط", activity_aliases: "اسم بديل", services: "خدمة", receivers: "مستقبِل", providers: "مزوّد محتوى" };

function Signal({ Icon, label, value, tone = "neutral", sub }) {
  return (
    <div className={`signal tone-${tone}`}>
      <span className="signal-icon"><Icon width={18} height={18} /></span>
      <span className="signal-body">
        <span className="signal-label">{label}</span>
        <span className="signal-value">{value}</span>
        {sub && <span className="signal-sub">{sub}</span>}
      </span>
    </div>
  );
}

function ListBox({ title, items, render, empty }) {
  return (
    <details className="list-box" open={items.length > 0 && items.length <= 6}>
      <summary><span>{title}</span><span className="badge">{items.length}</span></summary>
      {items.length === 0
        ? <p className="muted small">{empty}</p>
        : <ul className="ltr">{items.map((it, i) => <li key={i}>{render(it)}</li>)}</ul>}
    </details>
  );
}

export default function EngineInsights({ analysis }) {
  if (!analysis) return null;
  const apis = Object.entries(analysis.sensitive_api_categories || {}).sort((a, b) => b[1] - a[1]);
  const maxApi = Math.max(1, ...apis.map(([, n]) => n));
  const exposed = analysis.exposed_components || [];
  const servers = analysis.hardcoded_servers || [];
  const shell = analysis.shell_commands || [];
  const outside = analysis.permissions?.outside_model || [];
  const zipWarn = analysis.zip_warnings || [];
  const modules = Object.values(analysis.modules || {});
  const okModules = modules.filter((s) => s === "ok").length;
  const clear = analysis.cleartext;
  const signing = analysis.signing || {};
  const schemes = Object.entries(signing.schemes || {}).filter(([, v]) => v).map(([k]) => k.replace("v31", "v3.1"));

  return (
    <section className="card insights" id="engine">
      <div className="card-head">
        <div>
          <p className="kicker"><Layers width={14} height={14} /> تحليل المحرك الساكن</p>
          <h3>ماذا وجد المحرك داخل التطبيق؟</h3>
          <p className="muted small">
            معلومات وصفية من وحدات التحليل الـ {modules.length}، تساعد على فهم سلوك التطبيق.
            <strong> لا تدخل في قرار النموذج</strong>، ووجود أي منها ليس دليلاً على أن التطبيق خبيث.
          </p>
        </div>
        <span className={`badge ${okModules === modules.length ? "badge-good" : "badge-critical"}`}>
          <bdi className="ltr">{okModules}/{modules.length}</bdi> وحدة نجحت
        </span>
      </div>

      <div className="signals">
        <Signal Icon={Code} label="فئات API حساسة" value={apis.length}
                tone={apis.some(([k]) => SENSITIVE.has(k)) ? "warning" : "neutral"}
                sub={apis.filter(([k]) => SENSITIVE.has(k)).map(([k]) => API_AR[k] || k).slice(0, 2).join("، ") || "لا فئات عالية الحساسية"} />
        <Signal Icon={Layers} label="مكوّنات مكشوفة" value={exposed.length}
                tone={exposed.length > 5 ? "warning" : "neutral"} sub="يمكن لتطبيقات أخرى استدعاؤها" />
        <Signal Icon={clear?.permitted ? Unlock : Key} label="اتصال HTTP غير مشفّر"
                value={clear == null ? "—" : clear.permitted ? "مسموح" : "ممنوع"}
                tone={clear?.permitted ? "warning" : "good"}
                sub={clear?.decided_by === "network_security_config" ? "حسب Network Security Config" : clear?.decided_by === "manifest" ? "حسب الـ Manifest" : "القيمة الافتراضية"} />
        <Signal Icon={Fingerprint} label="التوقيع" value={schemes.length ? schemes.join(" · ") : "غير موقّع"}
                tone={!schemes.length || signing.debug_signed ? "critical" : "good"}
                sub={signing.debug_signed ? "شهادة Debug" : signing.verified == null ? "دون تحقق تشفيري" : signing.verified ? "تحقق apksigner" : "فشل التحقق"} />
        <Signal Icon={Server} label="خوادم مكتوبة في الكود" value={servers.length}
                tone={servers.length ? "warning" : "neutral"} sub="عناوين IP أو منافذ صريحة" />
        <Signal Icon={Terminal} label="أوامر نظام (shell)" value={shell.length}
                tone={shell.length ? "warning" : "neutral"} sub="نصوص تشبه أوامر shell" />
      </div>

      {apis.length > 0 && (
        <div className="api-bars">
          <h4>استدعاءات API الحساسة حسب الفئة <span className="muted small">(عدد مواضع الاستدعاء)</span></h4>
          {apis.map(([cat, n]) => (
            <div key={cat} className={`api-row ${SENSITIVE.has(cat) ? "hot" : ""}`}>
              <span className="api-name">{API_AR[cat] || cat}</span>
              <span className="api-track"><span style={{ width: `${Math.max(3, (n / maxApi) * 100)}%` }} /></span>
              <span className="api-count ltr">{n}</span>
            </div>
          ))}
        </div>
      )}

      <div className="list-grid">
        <ListBox title="المكوّنات المكشوفة" items={exposed} empty="لا مكوّنات مكشوفة دون حماية."
                 render={(c) => <><span className="tag">{COMPONENT_AR[c.type] || c.type}</span> {c.name}</>} />
        <ListBox title="أذونات خارج النموذج" items={outside} empty="كل أذونات Android في التطبيق يغطيها النموذج."
                 render={(p) => p.replace("android.permission.", "")} />
        <ListBox title="خوادم مكتوبة في الكود" items={servers} empty="لم تُكتشف عناوين خوادم صريحة."
                 render={(s) => s.value} />
        <ListBox title="أوامر النظام" items={shell} empty="لم تُكتشف أوامر shell." render={(s) => s} />
        {zipWarn.length > 0 && (
          <ListBox title="تحذيرات بنية الملف" items={zipWarn} empty=""
                   render={(w) => <><span className="tag tag-warn">{w.code}</span> {w.entry || w.message}</>} />
        )}
      </div>
      {clear?.cleartext_domains?.length > 0 && (
        <p className="muted small"><Globe width={14} height={14} /> نطاقات مسموح لها بـ HTTP غير المشفّر:
          <bdi className="ltr"> {clear.cleartext_domains.join(", ")}</bdi></p>
      )}
    </section>
  );
}
