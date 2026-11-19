"""
استخراج استدعاءات الـ APIs الحساسة من كود التطبيق، مع مكان كل استدعاء (caller).

كيف نجد الاستدعاءات؟
    في Dalvik bytecode كل استدعاء method هو تعليمة invoke-* تحمل رقماً (index) يشير
    إلى جدول method_ids في ملف DEX. لذلك نعمل على مرحلتين:
        1) نمر على جدول method_ids مرة واحدة (آلاف قليلة) ونحدد أي الأرقام تشير إلى API حساس.
        2) نمسح تعليمات كل method في التطبيق، ولكل invoke-* نفحص رقمه في مجموعة صغيرة (O(1)).
    إذا لم يحوِ ملف DEX أي إشارة إلى API حساس، نتخطى مسح تعليماته بالكامل.

حدود هذه الطريقة (نذكرها بصراحة):
    - التعليمة تحمل النوع الثابت (static type) المكتوب في الكود. استدعاء عبر صنف فرعي
      (مثل this.openFileOutput داخل Activity) يظهر باسم الصنف الفرعي فلا نطابقه.
    - الاستدعاءات عبر Reflection (Class.forName("android.telephony.SmsManager")) لا تظهر
      كاستدعاء مباشر؛ نرصد استخدام Reflection نفسه، والنصوص في strings_analyzer.
    - الكود المحمّل ديناميكياً أو المشفّر أو في مكتبات native لا يُرى في التحليل الثابت.
"""
from __future__ import annotations

from collections import defaultdict

from ..config import DEFAULT_DEX_LIMITS, DexLimits
from ..core.budget import TimeBudget
from .api_catalog import SENSITIVE_APIS, build_index, match
from .base import BaseAnalyzer
from .dex_analyzer import descriptor_to_java, method_signature

# invoke-virtual/super/direct/static/interface (+ /range) و invoke-polymorphic
INVOKE_OPCODES = frozenset({0x6E, 0x6F, 0x70, 0x71, 0x72, 0x74, 0x75, 0x76, 0x77, 0x78, 0xFA, 0xFB})
_INDEX = build_index()


def _sensitive_method_ids(dex) -> dict[int, tuple[str, str, str, str]]:
    """رقم method_id -> (category, signature, class_desc, method_name) للـ APIs الحساسة فقط."""
    out = {}
    cm = dex.get_class_manager()
    for idx in range(dex.get_len_methods()):
        ref = cm.get_method_ref(idx)
        cls, name = ref.get_class_name(), ref.get_name()
        category = match(_INDEX, cls, name)
        if category:
            out[idx] = (category, method_signature(cls, name, ref.get_descriptor()), cls, name)
    return out


class ApiAnalyzer(BaseAnalyzer):
    name = "api_calls"

    def __init__(self, limits: DexLimits = DEFAULT_DEX_LIMITS):
        self.limits = limits

    def analyze(self, apk) -> dict:
        budget = TimeBudget(self.limits.time_budget_seconds)
        found: dict[str, dict] = {}
        callers: dict[str, list[str]] = defaultdict(list)
        scanned_methods = 0

        for pd in apk.dex:
            if not pd.ok or budget.exceeded():
                continue
            targets = _sensitive_method_ids(pd.dex)
            if not targets:
                continue  # لا إشارة لأي API حساس في هذا الملف: لا داعي لمسح تعليماته
            for cls in pd.dex.get_classes():
                if budget.exceeded():
                    break
                for m in cls.get_methods():
                    if m.get_code() is None:
                        continue
                    scanned_methods += 1
                    caller = None
                    for ins in m.get_instructions():
                        if ins.get_op_value() not in INVOKE_OPCODES:
                            continue
                        hit = targets.get(ins.get_ref_kind())
                        if hit is None:
                            continue
                        category, sig, cdesc, mname = hit
                        entry = found.setdefault(sig, {
                            "category": category, "signature": sig,
                            "class": descriptor_to_java(cdesc), "method": mname, "call_sites": 0,
                        })
                        entry["call_sites"] += 1
                        caller = caller or method_signature(m.get_class_name(), m.get_name(), m.get_descriptor())
                        lst = callers[sig]
                        if len(lst) < self.limits.max_callers_per_api and caller not in lst:
                            lst.append(caller)

        calls = sorted(found.values(), key=lambda e: (e["category"], e["signature"]))
        for e in calls:
            e["callers"] = callers[e["signature"]]
            e["callers_truncated"] = e["call_sites"] > len(e["callers"])

        by_category = {}
        for cat in SENSITIVE_APIS:
            items = [e for e in calls if e["category"] == cat]
            if items:
                by_category[cat] = {"unique_apis": len(items),
                                    "call_sites": sum(e["call_sites"] for e in items),
                                    "apis": [e["signature"] for e in items]}
        return {
            "calls": calls,
            "by_category": by_category,
            "categories_present": list(by_category),
            "unique_sensitive_apis": len(calls),
            "total_call_sites": sum(e["call_sites"] for e in calls),
            "scanned_methods": scanned_methods,
            "truncated": {"time_budget": budget.hit},
            "elapsed_seconds": budget.elapsed,
            "note": "وجود API حساس معلومة وصفية وليس دليلاً على أن التطبيق خبيث",
        }
