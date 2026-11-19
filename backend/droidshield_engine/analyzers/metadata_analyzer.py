"""
البيانات الوصفية الأساسية للـ APK في مكان واحد (للتقرير وللواجهة).

يحسب أعداده بنفسه من الـ Manifest والـ ZIP بدل أخذها من analyzers أخرى، حتى يبقى مستقلاً:
لو فشل component_analyzer مثلاً، تبقى هذه الملخصات متوفرة.
"""
from __future__ import annotations

from .base import BaseAnalyzer
from .component_analyzer import COMPONENT_TAGS
from .manifest_xml import attr, children
from .permission_analyzer import REQUEST_TAGS


class MetadataAnalyzer(BaseAnalyzer):
    name = "metadata"

    def analyze(self, apk) -> dict:
        a = apk.apk
        manifest = a.get_android_manifest_xml()
        app = next(iter(children(manifest, "application")), None)
        try:
            app_name = a.get_app_name()
        except Exception:
            app_name = None
        permissions = {attr(e, "name") for t in REQUEST_TAGS for e in children(manifest, t)} - {None}
        names = apk.zip.entries
        return {
            "file_name": apk.file_name,
            "file_size": apk.size,
            "hashes": apk.hashes,
            "package": a.get_package(),
            "app_name": app_name,
            "version_name": a.get_androidversion_name(),
            "version_code": a.get_androidversion_code(),
            "min_sdk": a.get_min_sdk_version(),
            "target_sdk": a.get_target_sdk_version(),
            "dex_count": len(apk.zip.dex_files),
            "file_count": len(names),
            "resource_file_count": sum(n.startswith("res/") for n in names) + ("resources.arsc" in names),
            "native_library_count": sum(n.startswith("lib/") and n.endswith(".so") for n in names),
            "component_count": sum(len(children(app, t)) for t in COMPONENT_TAGS),
            "permission_count": len(permissions),
            "zip_warnings": len(apk.zip.warnings),
        }
