"""
الواجهة المشتركة لكل وحدات التحليل (Analyzers).

كل Analyzer:
    - له اسم ثابت (name) يُستخدم مفتاحاً في raw_analysis.json وفي سجل حالة الوحدات.
    - يستقبل LoadedApk (تم التحقق منه مسبقاً) ويعيد dict قابلاً للتحويل إلى JSON.
    - لا يعدّل LoadedApk ولا يعتمد على نتائج Analyzer آخر، حتى يمكن تشغيله أو
      فشله بشكل مستقل (فشل وحدة لا يُفقد نتائج البقية).

لماذا Abstract Base Class؟
    محرك التحليل (Phase 10) يتعامل مع قائمة Analyzers بشكل موحّد دون أن يعرف تفاصيلها،
    وإضافة وحدة جديدة لاحقاً = كلاس جديد فقط دون تعديل المحرك.
"""
from __future__ import annotations

from abc import ABC, abstractmethod
from typing import TYPE_CHECKING, Any, ClassVar

if TYPE_CHECKING:
    from ..core.apk_loader import LoadedApk


class BaseAnalyzer(ABC):
    name: ClassVar[str]

    @abstractmethod
    def analyze(self, apk: LoadedApk) -> dict[str, Any]:
        """يحلل الـ APK ويعيد النتائج. يرفع استثناءً عند الفشل (المحرك يلتقطه ويسجله)."""
