import { useEffect, useRef, useState } from "react";
import { getModelInfo, scanApk, scanFeatures } from "./api.js";
import { DEMOS } from "./demo.js";
import Header from "./components/Header.jsx";
import Uploader from "./components/Uploader.jsx";
import VerdictBanner from "./components/VerdictBanner.jsx";
import SafetyGauge from "./components/SafetyGauge.jsx";
import MetricTiles from "./components/MetricTiles.jsx";
import ShapWaterfall from "./components/ShapWaterfall.jsx";
import DetectedFeatures from "./components/DetectedFeatures.jsx";
import AppInfo from "./components/AppInfo.jsx";
import ModelCard from "./components/ModelCard.jsx";
import { Alert } from "./components/Icons.jsx";

export default function App() {
  const [phase, setPhase] = useState("idle"); // idle | uploading | analyzing | done | error
  const [progress, setProgress] = useState(0);
  const [result, setResult] = useState(null);
  const [source, setSource] = useState(null); // { kind: "apk" | "demo", name }
  const [error, setError] = useState("");
  const [modelInfo, setModelInfo] = useState(null);
  const [modelStatus, setModelStatus] = useState("loading"); // loading | online | offline
  const resultsRef = useRef(null);
  const demoStarted = useRef(false); // React StrictMode يشغّل التأثير مرتين في وضع التطوير
  const [theme, setTheme] = useState(() => {
    try { return localStorage.getItem("theme") || ""; } catch { return ""; }
  });

  useEffect(() => {
    // الخادم قد يحتاج ثوانٍ لتحميل النموذج عند التشغيل؛ نعيد المحاولة كل ثانيتين لمدة دقيقة
    let cancelled = false;
    let timer;
    const connect = (attempt = 0) => {
      getModelInfo()
        .then((m) => { if (!cancelled) { setModelInfo(m); setModelStatus("online"); } })
        .catch(() => {
          if (cancelled) return;
          if (attempt < 30) {
            setModelStatus(attempt < 3 ? "loading" : "offline");
            timer = setTimeout(() => connect(attempt + 1), 2000);
          } else {
            setModelStatus("offline");
          }
        });
    };
    connect();
    const demo = new URLSearchParams(window.location.hash.slice(1)).get("demo");
    if (demo && DEMOS[demo] && !demoStarted.current) {
      demoStarted.current = true;
      runDemo(demo);
    }
    return () => { cancelled = true; clearTimeout(timer); };
  }, []);

  useEffect(() => {
    if (theme) document.documentElement.dataset.theme = theme;
    else delete document.documentElement.dataset.theme;
    try { localStorage.setItem("theme", theme); } catch { /* ignore */ }
  }, [theme]);

  useEffect(() => {
    if (phase === "done") resultsRef.current?.scrollIntoView({ behavior: "smooth", block: "start" });
  }, [phase]);

  function begin(src) {
    setResult(null);
    setError("");
    setProgress(0);
    setSource(src);
  }

  async function handleFile(file) {
    begin({ kind: "apk", name: file.name });
    setPhase("uploading");
    try {
      const data = await scanApk(file, {
        onUploadProgress: setProgress,
        onUploaded: () => setPhase("analyzing"),
      });
      setResult(data);
      setPhase("done");
    } catch (e) {
      setError(e.message);
      setPhase("error");
    }
  }

  async function runDemo(key) {
    begin({ kind: "demo", name: DEMOS[key].title });
    setPhase("analyzing");
    try {
      setResult(await scanFeatures(DEMOS[key].features));
      setPhase("done");
    } catch (e) {
      setError(e.message);
      setPhase("error");
    }
  }

  function reset() {
    setPhase("idle");
    setResult(null);
    setSource(null);
    window.scrollTo({ top: 0, behavior: "smooth" });
  }

  const busy = phase === "uploading" || phase === "analyzing";
  const dark = theme === "dark" ||
    (!theme && window.matchMedia?.("(prefers-color-scheme: dark)").matches);

  return (
    <>
      <Header status={modelStatus} dark={dark} onToggleTheme={() => setTheme(dark ? "light" : "dark")} />

      <main className="page">
        {!result && (
          <section className="hero">
            <span className="eyebrow">تحليل ساكن · تعلّم آلي · ذكاء اصطناعي قابل للتفسير</span>
            <h1>افحص تطبيق أندرويد قبل تثبيته</h1>
            <p className="lead">
              ارفع ملف APK ليُفكَّك ويُحلَّل بنموذج SVM مدرّب على أكثر من 7,000 تطبيق،
              ثم تحصل على نسبة أمان وشرح مفصّل لسبب القرار.
            </p>
          </section>
        )}

        {!result && (
          <Uploader onFile={handleFile} onDemo={runDemo} disabled={busy}
                    phase={phase} progress={progress} source={source} />
        )}

        {phase === "error" && (
          <div className="card alert" role="alert">
            <Alert className="alert-icon" />
            <div>
              <p className="strong">تعذّر إكمال الفحص</p>
              <p className="muted">{error}</p>
            </div>
          </div>
        )}

        {result && (
          <div className="results" ref={resultsRef}>
            <VerdictBanner result={result} source={source} onReset={reset} />
            <div className="grid-2">
              <SafetyGauge result={result} />
              <MetricTiles result={result} />
            </div>
            {result.explanation && <ShapWaterfall explanation={result.explanation} />}
            <div className="grid-2">
              <DetectedFeatures result={result} />
              <AppInfo result={result} />
            </div>
          </div>
        )}

        <ModelCard info={modelInfo} />
      </main>
    </>
  );
}
