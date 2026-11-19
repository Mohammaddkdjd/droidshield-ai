"""
تحليل الأذونات في AndroidManifest.xml.

يفرّق بين ثلاثة أشياء مختلفة تماماً:
    requested -> أذونات يطلبها التطبيق (<uses-permission> و <uses-permission-sdk-23>)
    declared  -> أذونات يعرّفها التطبيق لغيره (<permission>)؛ التعريف ليس طلباً
    implied   -> أذونات يضيفها Android ضمنياً للتطبيقات القديمة (غير مكتوبة في الـ Manifest)

ولا يفترض أن الطلب = المنح: الأذونات الخطرة (dangerous) يمنحها المستخدم وقت التشغيل،
وأذونات signature لا تُمنح إطلاقاً لتطبيق عادي. نحن نسجّل ما *يطلبه* التطبيق فقط.

لماذا نقرأ الـ XML بأنفسنا بدل apk.get_permissions()؟
    في Androguard 4.1.4 تقرأ get_permissions() وسم <uses-permission> فقط وتتجاهل
    <uses-permission-sdk-23> تماماً، فيضيع إذن يطلبه التطبيق فعلاً.

ملاحظة عن موضع الوسوم: Android يقبل <uses-permission> فقط كابن مباشر لـ <manifest>.
الوسوم في أماكن أخرى (مثلاً داخل <application>) يتجاهلها النظام، فنسجّلها في
misplaced ولا نعدّها طلباً.
"""
from __future__ import annotations

from collections import Counter

from lxml import etree

from .aosp_permissions import all_known_permissions, decode_protection_level, permissions_for_api
from .base import BaseAnalyzer
from .manifest_xml import attr, children, parse_int

REQUEST_TAGS = ("uses-permission", "uses-permission-sdk-23")
ANDROID_PREFIX = "android.permission."


def extract_permissions(manifest: etree._Element, package: str, target_sdk: int) -> dict:
    """دالة نقية على شجرة الـ Manifest: سهلة الاختبار بـ XML مكتوب يدوياً."""
    aosp_known = all_known_permissions()
    aosp_details = permissions_for_api(target_sdk)

    # ------------------------------ declared ------------------------------ #
    declared = []
    for el in children(manifest, "permission"):
        name = attr(el, "name")
        if name:
            declared.append({
                "name": name,
                "protection_level": decode_protection_level(attr(el, "protectionLevel")),
                "permission_group": attr(el, "permissionGroup"),
                "label": attr(el, "label"),
                "description": attr(el, "description"),
            })
    declared_names = {d["name"] for d in declared}

    # ------------------------------ requested ----------------------------- #
    occurrences: list[tuple[str, str, int | None]] = []
    invalid = 0
    for tag in REQUEST_TAGS:
        for el in children(manifest, tag):
            name = (attr(el, "name") or "").strip()
            if not name:
                invalid += 1
                continue
            occurrences.append((name, tag, parse_int(attr(el, "maxSdkVersion"))))

    counts = Counter(n for n, _, _ in occurrences)
    merged: dict[str, dict] = {}
    for name, tag, max_sdk in occurrences:
        entry = merged.setdefault(name, {"name": name, "tags": [], "max_sdk_version": max_sdk})
        if tag not in entry["tags"]:
            entry["tags"].append(tag)

    requested = []
    for name in sorted(merged):
        entry = merged[name]
        if name in aosp_known:
            category = "aosp"
        elif name in declared_names:
            category = "declared_by_app"
        elif name.startswith(ANDROID_PREFIX):
            # يبدأ بـ android.permission. لكنه ليس في قاعدة AOSP. الأسباب المحتملة:
            #   - أحدث من القاعدة (مثل ACCESS_LOCAL_NETWORK في API 37 والقاعدة حتى 36)
            #   - يعرّفه تطبيق نظام لا الـ framework (مثل DOWNLOAD_WITHOUT_NOTIFICATION)
            #   - خطأ إملائي أو اسم مزيّف
            # لذلك هو "غير معروف للقاعدة" وليس "مزيّفاً". ويبقى يدخل المتجه إن كان ضمن الـ Schema.
            category = "unrecognized_android"
        else:
            category = "custom"
        info = aosp_details.get(name, {})
        level = info.get("protectionLevel")
        entry.update({
            "category": category,
            # نفس صيغة declared: {"raw": "normal|instant", "base": "normal", "flags": ["instant"]}
            "protection_level": decode_protection_level(level) if level else None,
            "permission_group": info.get("permissionGroup") or None,
            "label": info.get("label") or None,
        })
        requested.append(entry)

    misplaced = sorted({
        attr(el, "name") or "" for tag in REQUEST_TAGS for el in manifest.iter(tag)
        if el.getparent() is not manifest
    } - {""})

    by_level: dict[str, list[str]] = {}
    for r in requested:
        if r["protection_level"]:
            by_level.setdefault(r["protection_level"]["base"], []).append(r["name"])

    names = [r["name"] for r in requested]
    return {
        "requested": requested,
        "requested_names": names,
        "android_permissions": [n for n in names if n.startswith(ANDROID_PREFIX)],
        "sdk23_only": [r["name"] for r in requested if r["tags"] == ["uses-permission-sdk-23"]],
        "duplicates": sorted(n for n, k in counts.items() if k > 1),
        "unrecognized_android": [r["name"] for r in requested if r["category"] == "unrecognized_android"],
        "custom": [r["name"] for r in requested if r["category"] == "custom"],
        "by_protection_level": by_level,
        "declared": declared,
        "declared_groups": [attr(e, "name") for e in children(manifest, "permission-group")],
        "declared_trees": [attr(e, "name") for e in children(manifest, "permission-tree")],
        "misplaced": misplaced,
        "invalid_entries": invalid,
        "counts": {
            "requested": len(requested),
            "android": sum(n.startswith(ANDROID_PREFIX) for n in names),
            "dangerous": len(by_level.get("dangerous", [])),
            "custom": sum(r["category"] == "custom" for r in requested),
            "declared": len(declared),
        },
        "aosp_reference_api": target_sdk,
    }


class PermissionAnalyzer(BaseAnalyzer):
    name = "permissions"

    def analyze(self, apk) -> dict:
        a = apk.apk
        result = extract_permissions(a.get_android_manifest_xml(), a.get_package(),
                                     int(a.get_effective_target_sdk_version()))
        # implied: نحفظها للمعلومة فقط، ولا تدخل requested ولا المتجه
        result["implied"] = sorted({p[0] if isinstance(p, (list, tuple)) else p
                                    for p in a.get_uses_implied_permission_list()})
        return result
