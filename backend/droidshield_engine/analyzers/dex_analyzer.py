"""
تحليل بنية الكود في كل ملفات DEX (Multi-DEX مدعوم).

ماذا يوجد في ملف DEX؟
    DEX هو صيغة الكود المترجم لـ Android (Dalvik bytecode). يحوي جداول:
    class_defs (الأصناف المعرَّفة في التطبيق)، method_ids/field_ids (كل method/field
    يُشار إليه، معرّفاً هنا أو في Android نفسه)، و code_items (التعليمات).
    Androguard يحلل هذه الجداول ويعطينا ClassDefItem و EncodedMethod و EncodedField.

أسماء الأصناف في DEX بصيغة الـ descriptor: Lcom/example/Main;  -> نحوّلها إلى com.example.Main

ما نحسبه:
    - الأعداد الكاملة (دائماً كاملة، مهما كان حجم التطبيق)
    - قائمة كل الأصناف، وتفاصيل methods و fields لأصناف التطبيق خارج المكتبات المعروفة
      (المكتبات قد تكون 90% من الكود وتضخّم النتيجة إلى عشرات الـ MB دون فائدة أمنية)،
      وكل قائمة لها حد أقصى مع علامة truncated
    - native / static / abstract methods
    - الأصناف المكررة بين ملفات DEX
    - إحصاءات التسمية: نسبة الأسماء ذات الحرف الواحد (مؤشر على التعمية بـ ProGuard/R8،
      وهي شائعة في التطبيقات السليمة أيضاً، فليست دليلاً على خبث)
"""
from __future__ import annotations

from collections import Counter

from ..config import DEFAULT_DEX_LIMITS, DexLimits
from ..core.budget import TimeBudget
from .base import BaseAnalyzer

ACC_STATIC, ACC_NATIVE, ACC_ABSTRACT = 0x8, 0x100, 0x400
ACC_SYNTHETIC, ACC_CONSTRUCTOR = 0x1000, 0x10000

# مكتبات شائعة معروفة. تفاصيل methods/fields تُحفظ فقط للأصناف خارجها (مع عدّ الكل).
# لماذا قائمة مكتبات وليس "اسم الحزمة يبدأ باسم التطبيق"؟ لأن البرمجيات الخبيثة كثيراً ما
# تضع كودها في حزم عشوائية (a.b.c) لا تشبه اسم التطبيق؛ بهذه الطريقة يبقى كودها ظاهراً.
KNOWN_LIBRARY_PREFIXES = (
    "android.", "androidx.", "com.android.", "dalvik.", "java.", "javax.", "kotlin.", "kotlinx.",
    "j$.", "com.google.", "org.jetbrains.", "org.intellij.", "okhttp3.", "okio.", "retrofit2.",
    "com.squareup.", "io.reactivex.", "org.apache.", "org.json.", "com.fasterxml.", "org.slf4j.",
    "dagger.", "javax.inject.", "com.bumptech.glide.", "coil.", "coil3.", "io.coil_kt.",
    "com.facebook.", "org.bouncycastle.", "org.chromium.", "_COROUTINE.",
)


def is_library_class(java_name: str) -> bool:
    return java_name.startswith(KNOWN_LIBRARY_PREFIXES)


def descriptor_to_java(desc: str) -> str:
    """Lcom/a/B; -> com.a.B ؛ أي صيغة أخرى تُعاد كما هي."""
    if desc.startswith("L") and desc.endswith(";"):
        return desc[1:-1].replace("/", ".")
    return desc


def package_of(java_name: str) -> str:
    return java_name.rsplit(".", 1)[0] if "." in java_name else "(default)"


def method_signature(class_desc: str, name: str, descriptor: str) -> str:
    """
    الصيغة القياسية في أدوات Android: Lcom/a/B;->foo(ILjava/lang/String;)V
    Androguard يضع مسافات بين المعاملات "(I Ljava/lang/String;)V" فنحذفها.
    """
    return f"{class_desc}->{name}{descriptor.replace(' ', '')}"


def _short_ratio(names: list[str]) -> float:
    names = [n for n in names if n and not n.startswith("<")]
    return round(sum(len(n) == 1 for n in names) / len(names), 4) if names else 0.0


class DexAnalyzer(BaseAnalyzer):
    name = "dex"

    def __init__(self, limits: DexLimits = DEFAULT_DEX_LIMITS):
        self.limits = limits

    def analyze(self, apk) -> dict:
        lim, budget = self.limits, TimeBudget(self.limits.time_budget_seconds)
        files, classes, methods, fields, native = [], [], [], [], []
        totals = Counter()
        packages = Counter()
        class_home: dict[str, str] = {}
        duplicates: set[str] = set()
        simple_class_names, method_names = [], []

        for pd in apk.dex:
            info = {"name": pd.name, "size": pd.size, "version": pd.version, "error": pd.error}
            files.append(info)
            if not pd.ok or budget.hit:
                continue
            d = pd.dex
            info.update(classes=0, methods=0, fields=0,
                        method_ids=d.get_len_methods(), strings=d.get_len_strings())
            for cls in d.get_classes():
                if budget.exceeded():
                    break
                cdesc = cls.get_name()
                jname = descriptor_to_java(cdesc)
                if cdesc in class_home:
                    duplicates.add(jname)   # Android يحمّل النسخة من أول DEX فقط
                else:
                    class_home[cdesc] = pd.name
                cmethods, cfields = cls.get_methods(), cls.get_fields()
                info["classes"] += 1
                info["methods"] += len(cmethods)
                info["fields"] += len(cfields)
                packages[package_of(jname)] += 1
                simple_class_names.append(jname.rsplit(".", 1)[-1].split("$")[-1])
                library = is_library_class(jname)
                totals["library_classes"] += library

                if len(classes) < lim.max_listed_classes:
                    classes.append({
                        "name": jname,
                        "dex": pd.name,
                        "access": cls.get_access_flags_string(),
                        "superclass": descriptor_to_java(cls.get_superclassname() or ""),
                        "interfaces": [descriptor_to_java(i) for i in (cls.get_interfaces() or [])],
                        "methods": len(cmethods),
                        "fields": len(cfields),
                        "library": library,
                    })
                for m in cmethods:
                    flags, mname = m.get_access_flags(), m.get_name()
                    method_names.append(mname)
                    totals["static"] += bool(flags & ACC_STATIC)
                    totals["abstract"] += bool(flags & ACC_ABSTRACT)
                    totals["synthetic"] += bool(flags & ACC_SYNTHETIC)
                    totals["constructors"] += bool(flags & ACC_CONSTRUCTOR)
                    # التوقيع يُبنى فقط إذا سيُحفظ (Phase 9: بناؤه لكل method في المكتبات
                    # كان يضاعف الوقت على تطبيق بـ 17 ألف صنف مكتبات)
                    is_native = bool(flags & ACC_NATIVE)
                    keep_native = is_native and len(native) < lim.max_listed_native
                    keep_method = not library and len(methods) < lim.max_listed_methods
                    sig = method_signature(cdesc, mname, m.get_descriptor()) if keep_native or keep_method else None
                    if is_native:
                        totals["native"] += 1
                        if keep_native:
                            native.append(sig)
                    if not library:
                        totals["listable_methods"] += 1
                        if keep_method:
                            methods.append({"signature": sig, "access": m.get_access_flags_string()})
                if library:
                    continue
                for f in cfields:
                    totals["listable_fields"] += 1
                    if len(fields) < lim.max_listed_fields:
                        fields.append({"signature": f"{cdesc}->{f.get_name()}:{f.get_descriptor()}",
                                       "access": f.get_access_flags_string()})

        n_classes = sum(f.get("classes", 0) for f in files)
        n_methods = sum(f.get("methods", 0) for f in files)
        n_fields = sum(f.get("fields", 0) for f in files)
        return {
            "dex_files": files,
            "dex_count": len(files),
            "multidex": len(files) > 1,
            "totals": {
                "classes": n_classes, "methods": n_methods, "fields": n_fields,
                "native_methods": totals["native"], "static_methods": totals["static"],
                "abstract_methods": totals["abstract"], "synthetic_methods": totals["synthetic"],
                "constructors": totals["constructors"],
                "library_classes": totals["library_classes"],
                "non_library_classes": n_classes - totals["library_classes"],
            },
            "listing_scope": "classes: الكل ؛ methods و fields: أصناف خارج المكتبات المعروفة فقط",
            "top_packages": dict(packages.most_common(100)),
            "package_count": len(packages),
            "classes": classes,
            "methods": methods,
            "fields": fields,
            "native_methods": native,
            "duplicate_classes": sorted(duplicates),
            "naming": {
                "single_char_class_ratio": _short_ratio(simple_class_names),
                "single_char_method_ratio": _short_ratio(method_names),
            },
            "truncated": {
                "time_budget": budget.hit,
                "classes": n_classes > len(classes),
                "methods": totals["listable_methods"] > len(methods),
                "fields": totals["listable_fields"] > len(fields),
                "native_methods": totals["native"] > len(native),
            },
            "elapsed_seconds": budget.elapsed,
        }
