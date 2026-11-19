"""يضيف مجلد backend إلى sys.path حتى يعمل `import droidshield_engine` من أي مكان يُشغَّل منه pytest."""
import sys
from pathlib import Path

BACKEND_DIR = Path(__file__).resolve().parents[2]
if str(BACKEND_DIR) not in sys.path:
    sys.path.insert(0, str(BACKEND_DIR))


TEST_TMP = Path("E:/apk_test/pytest_tmp")  # القرص C: شبه ممتلئ؛ ملفات APK المعدّلة في الاختبارات كبيرة


def pytest_configure(config):
    # تشغيل الاختبارات السريعة فقط: pytest -m "not slow"
    config.addinivalue_line("markers", "slow: اختبار بطيء يستخدم مرجعاً مستقلاً ثقيلاً (Androguard xref)")
    # pytest يفرّغ هذا المجلد في بداية كل تشغيل، فلا تتراكم الملفات المؤقتة
    if config.option.basetemp is None and TEST_TMP.parent.exists():
        config.option.basetemp = str(TEST_TMP)
