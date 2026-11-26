// أيقونات SVG خطية موحّدة (stroke = currentColor) بدل الإيموجي
const base = {
  width: 20, height: 20, viewBox: "0 0 24 24", fill: "none",
  stroke: "currentColor", strokeWidth: 1.8, strokeLinecap: "round", strokeLinejoin: "round",
  "aria-hidden": true,
};

export const Shield = (p) => (
  <svg {...base} {...p}><path d="M12 3l7 3v6c0 4.5-3 8-7 9-4-1-7-4.5-7-9V6l7-3z" /><path d="M9 12l2 2 4-4" /></svg>
);
export const Upload = (p) => (
  <svg {...base} {...p}><path d="M12 16V4" /><path d="M7 9l5-5 5 5" /><path d="M4 16v3a1 1 0 001 1h14a1 1 0 001-1v-3" /></svg>
);
export const Check = (p) => (
  <svg {...base} {...p}><path d="M5 12.5l4.5 4.5L19 7.5" /></svg>
);
export const CheckCircle = (p) => (
  <svg {...base} {...p}><circle cx="12" cy="12" r="9" /><path d="M8 12.5l2.5 2.5L16 9.5" /></svg>
);
export const Alert = (p) => (
  <svg {...base} {...p}><path d="M12 4l9 16H3l9-16z" /><path d="M12 10v4" /><path d="M12 17.5v.01" /></svg>
);
export const Octagon = (p) => (
  <svg {...base} {...p}><path d="M8.5 3h7L21 8.5v7L15.5 21h-7L3 15.5v-7L8.5 3z" /><path d="M9.5 9.5l5 5M14.5 9.5l-5 5" /></svg>
);
export const Download = (p) => (
  <svg {...base} {...p}><path d="M12 4v12" /><path d="M7 11l5 5 5-5" /><path d="M4 20h16" /></svg>
);
export const Refresh = (p) => (
  <svg {...base} {...p}><path d="M20 11a8 8 0 10-2.3 5.7" /><path d="M20 5v6h-6" /></svg>
);
export const Moon = (p) => (
  <svg {...base} {...p}><path d="M20 14.5A8 8 0 019.5 4a8 8 0 1010.5 10.5z" /></svg>
);
export const Sun = (p) => (
  <svg {...base} {...p}><circle cx="12" cy="12" r="4" /><path d="M12 2v2M12 20v2M2 12h2M20 12h2M4.9 4.9l1.4 1.4M17.7 17.7l1.4 1.4M4.9 19.1l1.4-1.4M17.7 6.3l1.4-1.4" /></svg>
);
export const Lock = (p) => (
  <svg {...base} {...p}><rect x="5" y="11" width="14" height="9" rx="2" /><path d="M8 11V8a4 4 0 018 0v3" /></svg>
);
export const Eye = (p) => (
  <svg {...base} {...p}><path d="M2 12s3.5-7 10-7 10 7 10 7-3.5 7-10 7S2 12 2 12z" /><circle cx="12" cy="12" r="3" /></svg>
);
export const Trash = (p) => (
  <svg {...base} {...p}><path d="M4 7h16" /><path d="M10 11v6M14 11v6" /><path d="M6 7l1 13h10l1-13" /><path d="M9 7V4h6v3" /></svg>
);
export const Package = (p) => (
  <svg {...base} {...p}><path d="M12 3l8 4.5v9L12 21l-8-4.5v-9L12 3z" /><path d="M4 7.5l8 4.5 8-4.5" /><path d="M12 12v9" /></svg>
);
export const Beaker = (p) => (
  <svg {...base} {...p}><path d="M9 3h6" /><path d="M10 3v6l-5 9a2 2 0 001.7 3h10.6a2 2 0 001.7-3l-5-9V3" /><path d="M7.5 15h9" /></svg>
);
export const Cpu = (p) => (
  <svg {...base} {...p}><rect x="6" y="6" width="12" height="12" rx="2" /><rect x="9.5" y="9.5" width="5" height="5" /><path d="M9 2v3M15 2v3M9 19v3M15 19v3M2 9h3M2 15h3M19 9h3M19 15h3" /></svg>
);
export const Table = (p) => (
  <svg {...base} {...p}><rect x="3" y="4" width="18" height="16" rx="2" /><path d="M3 10h18M3 15h18M9 4v16" /></svg>
);
export const Chart = (p) => (
  <svg {...base} {...p}><path d="M4 20h16" /><path d="M7 16V9M12 16V5M17 16v-4" /></svg>
);
export const Github = (p) => (
  <svg {...base} {...p}><path d="M9 19c-4.3 1.4-4.3-2.5-6-3m12 5v-3.5c0-1 .1-1.4-.5-2 2.8-.3 5.5-1.4 5.5-6a4.6 4.6 0 00-1.3-3.2 4.2 4.2 0 00-.1-3.2s-1.1-.3-3.5 1.3a12.3 12.3 0 00-6.2 0C6.5 2.8 5.4 3.1 5.4 3.1a4.2 4.2 0 00-.1 3.2A4.6 4.6 0 004 9.5c0 4.6 2.7 5.7 5.5 6-.6.6-.6 1.2-.5 2V21" /></svg>
);
export const Code = (p) => (
  <svg {...base} {...p}><path d="M8 7l-5 5 5 5M16 7l5 5-5 5M13.5 4l-3 16" /></svg>
);
export const Globe = (p) => (
  <svg {...base} {...p}><circle cx="12" cy="12" r="9" /><path d="M3 12h18M12 3a14 14 0 010 18M12 3a14 14 0 000 18" /></svg>
);
export const Key = (p) => (
  <svg {...base} {...p}><circle cx="8" cy="15" r="4" /><path d="M10.8 12.2L20 3M16 7l3 3M14 9l2 2" /></svg>
);
export const Terminal = (p) => (
  <svg {...base} {...p}><rect x="3" y="4" width="18" height="16" rx="2" /><path d="M7 9l3 3-3 3M12 15h5" /></svg>
);
export const Server = (p) => (
  <svg {...base} {...p}><rect x="3" y="4" width="18" height="7" rx="2" /><rect x="3" y="13" width="18" height="7" rx="2" /><path d="M7 7.5h.01M7 16.5h.01" /></svg>
);
export const Layers = (p) => (
  <svg {...base} {...p}><path d="M12 3l9 5-9 5-9-5 9-5z" /><path d="M3 13l9 5 9-5" /></svg>
);
export const Unlock = (p) => (
  <svg {...base} {...p}><rect x="5" y="11" width="14" height="9" rx="2" /><path d="M8 11V8a4 4 0 017.5-2" /></svg>
);
export const Gauge = (p) => (
  <svg {...base} {...p}><path d="M4 16a8 8 0 1116 0" /><path d="M12 16l4-5" /><circle cx="12" cy="16" r="1" /></svg>
);
export const Clock = (p) => (
  <svg {...base} {...p}><circle cx="12" cy="12" r="9" /><path d="M12 7v5l3 2" /></svg>
);
export const Sparkle = (p) => (
  <svg {...base} {...p}><path d="M12 3l1.8 5.2L19 10l-5.2 1.8L12 17l-1.8-5.2L5 10l5.2-1.8L12 3z" /><path d="M19 16l.8 2.2L22 19l-2.2.8L19 22l-.8-2.2L16 19l2.2-.8L19 16z" /></svg>
);
export const Fingerprint = (p) => (
  <svg {...base} {...p}><path d="M12 11v3a8 8 0 01-1.5 4.6M8 10a4 4 0 018 0v2.5M5 8.5a8 8 0 0114 0M5.5 14a12 12 0 00.6-4M17.5 16.5A16 16 0 0018 12" /></svg>
);
