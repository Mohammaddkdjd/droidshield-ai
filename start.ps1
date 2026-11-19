# تشغيل المشروع كاملاً بأمر واحد (بدون VS Code):
#   powershell -ExecutionPolicy Bypass -File .\start.ps1
# يفتح نافذتين: الخادم (8000) والواجهة (5173)، ثم يفتح المتصفح عندما يجهز كل شيء.

$root = $PSScriptRoot
$python = Join-Path $root ".venv\Scripts\python.exe"

if (-not (Test-Path $python)) {
    Write-Host "إنشاء بيئة Python وتثبيت المتطلبات..." -ForegroundColor Yellow
    python -m venv (Join-Path $root ".venv")
    & $python -m pip install -r (Join-Path $root "backend\requirements.txt")
}
if (-not (Test-Path (Join-Path $root "frontend\node_modules"))) {
    Write-Host "تثبيت حزم الواجهة..." -ForegroundColor Yellow
    Push-Location (Join-Path $root "frontend"); npm install; Pop-Location
}
if (-not (Test-Path (Join-Path $root "backend\models\droidshield\svm_rbf.joblib"))) {
    Write-Host "النموذج غير موجود. شغّل التدريب أولاً: python backend\ml\train_droidshield.py" -ForegroundColor Red
    exit 1
}

$env:PYTHONIOENCODING = "utf-8"; $env:PYTHONWARNINGS = "ignore"
Start-Process powershell -ArgumentList "-NoExit", "-Command", "`$Host.UI.RawUI.WindowTitle='Backend :8000'; & '$python' -m uvicorn app.main:app --port 8000 --reload" -WorkingDirectory (Join-Path $root "backend")
Start-Process powershell -ArgumentList "-NoExit", "-Command", "`$Host.UI.RawUI.WindowTitle='Frontend :5173'; npm run dev -- --port 5173 --strictPort" -WorkingDirectory (Join-Path $root "frontend")

Write-Host "بانتظار جاهزية الخادمين..." -ForegroundColor Cyan
for ($i = 0; $i -lt 90; $i++) {
    Start-Sleep -Seconds 1
    try {
        Invoke-WebRequest -UseBasicParsing -TimeoutSec 2 http://localhost:8000/health | Out-Null
        Invoke-WebRequest -UseBasicParsing -TimeoutSec 2 http://localhost:5173 | Out-Null
        Start-Process "http://localhost:5173"
        Write-Host "جاهز: http://localhost:5173" -ForegroundColor Green
        exit 0
    } catch { }
}
Write-Host "لم يجهز الخادمان خلال 90 ثانية. راجع نافذتي الخادم والواجهة." -ForegroundColor Red
