import { Moon, Shield, Sun } from "./Icons.jsx";

const STATUS = {
  loading: { label: "جارٍ الاتصال بالنموذج", cls: "st-loading" },
  online: { label: "النموذج متصل", cls: "st-online" },
  offline: { label: "الخادم غير متصل", cls: "st-offline" },
};

export default function Header({ status, dark, onToggleTheme }) {
  const s = STATUS[status];
  return (
    <header className="nav">
      <div className="nav-inner">
        <div className="brand">
          <span className="brand-mark"><Shield width={22} height={22} /></span>
          <div>
            <div className="brand-name">درع أندرويد</div>
            <div className="brand-sub">Android Malware XAI</div>
          </div>
        </div>
        <div className="nav-actions">
          <span className={`status ${s.cls}`} role="status">
            <i className="dot" aria-hidden />{s.label}
          </span>
          <button className="icon-btn" onClick={onToggleTheme}
                  aria-label={dark ? "التبديل إلى الوضع الفاتح" : "التبديل إلى الوضع الداكن"}>
            {dark ? <Sun /> : <Moon />}
          </button>
        </div>
      </div>
    </header>
  );
}
