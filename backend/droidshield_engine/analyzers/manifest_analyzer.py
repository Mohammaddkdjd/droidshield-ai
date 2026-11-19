"""
تحليل معلومات التطبيق العامة من AndroidManifest.xml.

لكل خاصية أمنية في <application> نحفظ ثلاثة أشياء:
    raw          -> القيمة كما هي مكتوبة (أو None إن لم تُكتب)
    value        -> القيمة الفعلية التي سيطبقها Android (بما فيها القيمة الافتراضية)
    default_used -> هل أخذنا القيمة الافتراضية لأن الخاصية غير مكتوبة؟
لأن غياب الخاصية له معنى: مثلاً allowBackup غير المكتوبة = true (النسخ الاحتياطي مسموح).

usesCleartextTraffic: القيمة الافتراضية true إذا كان targetSdk < 28، وإلا false.
لكن networkSecurityConfig (إن وُجد) يتقدم عليها؛ تحليله في resources_analyzer (Phase 6).
"""
from __future__ import annotations

import re

from lxml import etree

from .base import BaseAnalyzer
from .manifest_xml import attr, bool_flag, children, parse_int, resolve_class_name

_PACKAGE_RE = re.compile(r"^[A-Za-z][A-Za-z0-9_]*(\.[A-Za-z][A-Za-z0-9_]*)+$")


def extract_manifest_info(manifest: etree._Element, package: str, target_sdk: int) -> dict:
    app = next(iter(children(manifest, "application")), None)
    queries = next(iter(children(manifest, "queries")), None)

    flags = {
        "debuggable": bool_flag(app, "debuggable", False),
        "allow_backup": bool_flag(app, "allowBackup", True),
        "uses_cleartext_traffic": bool_flag(app, "usesCleartextTraffic", target_sdk < 28),
        "test_only": bool_flag(app, "testOnly", False),
        "has_code": bool_flag(app, "hasCode", True),
        "large_heap": bool_flag(app, "largeHeap", False),
        "persistent": bool_flag(app, "persistent", False),
        "extract_native_libs": bool_flag(app, "extractNativeLibs", True),
        "request_legacy_external_storage": bool_flag(app, "requestLegacyExternalStorage", False),
        "enabled": bool_flag(app, "enabled", True),
    }
    get = (lambda n: attr(app, n)) if app is not None else (lambda n: None)

    return {
        "package": package,
        "package_name_valid": bool(_PACKAGE_RE.match(package or "")),
        "version_code": attr(manifest, "versionCode"),
        "version_name": attr(manifest, "versionName"),
        "compile_sdk": parse_int(attr(manifest, "compileSdkVersion") or manifest.get("platformBuildVersionCode")),
        "shared_user_id": attr(manifest, "sharedUserId"),
        "install_location": attr(manifest, "installLocation"),
        "application": {
            "class_name": resolve_class_name(get("name"), package),
            "permission": get("permission"),
            "process": get("process"),
            "app_component_factory": get("appComponentFactory"),
            "network_security_config": get("networkSecurityConfig"),
            "full_backup_content": get("fullBackupContent"),
            "data_extraction_rules": get("dataExtractionRules"),
            "backup_agent": resolve_class_name(get("backupAgent"), package),
        },
        "flags": flags,
        "cleartext_note": ("networkSecurityConfig موجود وقد يغيّر سياسة cleartext؛ راجع resources"
                           if get("networkSecurityConfig") else None),
        "uses_libraries": [{"name": attr(e, "name"), "required": bool_flag(e, "required", True)["value"]}
                           for tag in ("uses-library", "uses-native-library") for e in children(app, tag)],
        "instrumentation": [resolve_class_name(attr(e, "name"), package)
                            for e in children(manifest, "instrumentation")],
        "queries": {
            "packages": [attr(e, "name") for e in children(queries, "package")],
            "intents": len(children(queries, "intent")),
            "providers": [attr(e, "authorities") for e in children(queries, "provider")],
        },
    }


class ManifestAnalyzer(BaseAnalyzer):
    name = "manifest"

    def analyze(self, apk) -> dict:
        a = apk.apk
        target = int(a.get_effective_target_sdk_version())
        info = extract_manifest_info(a.get_android_manifest_xml(), a.get_package(), target)
        try:
            app_name = a.get_app_name()  # يحلّ مرجع @string عبر resources.arsc
        except Exception:
            app_name = None
        info.update({
            "app_name": app_name,
            "min_sdk": parse_int(a.get_min_sdk_version()),
            "target_sdk": parse_int(a.get_target_sdk_version()),
            "max_sdk": parse_int(a.get_max_sdk_version()),
            "effective_target_sdk": target,
        })
        return info
