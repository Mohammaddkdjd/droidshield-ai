import { Github, Moon, Shield, Sun } from "./Icons.jsx";

const REPO_URL = "https://github.com/Mohammaddkdjd/droidshield-ai";

const STATUS = {
  loading: { label: "جارٍ الاتصال", cls: "st-loading" },
  online: { label: "النموذج جاهز", cls: "st-online" },
  offline: { label: "الخادم غير متصل", cls: "st-offline" },
};

export default function Header({ status, dark, onToggleTheme, onHome }) {
  const s = STATUS[status];
  return (
    <header className="nav">
      <div className="nav-inner">
        <button className="brand" onClick={onHome} aria-label="الصفحة الرئيسية">
          <span className="brand-mark"><Shield width={22} height={22} /></span>
          <span className="brand-text">
            <span className="brand-name ltr">DroidShield <b>AI</b></span>
            <span className="brand-sub">درع أندرويد · كشف البرمجيات الخبيثة</span>
          </span>
        </button>
        <div className="nav-actions">
          <span className={`status ${s.cls}`} role="status">
            <i className="dot" aria-hidden />
            <span className="status-label">{s.label}</span>
          </span>
          <a className="icon-btn" href={REPO_URL} target="_blank" rel="noreferrer" aria-label="الكود المصدري على GitHub">
            <Github width={19} height={19} />
          </a>
          <button className="icon-btn" onClick={onToggleTheme}
                  aria-label={dark ? "التبديل إلى الوضع الفاتح" : "التبديل إلى الوضع الداكن"}>
            {dark ? <Sun width={19} height={19} /> : <Moon width={19} height={19} />}
          </button>
        </div>
      </div>
    </header>
  );
}
