"""
تحليل ميزات العتاد المطلوبة (<uses-feature>) في AndroidManifest.xml.

<uses-feature android:name="android.hardware.camera" android:required="false"/>
    required=true (الافتراضي) -> متجر Google Play لا يعرض التطبيق لجهاز بلا هذه الميزة
    required=false            -> التطبيق يستخدمها إن وُجدت

لماذا نقرأ الـ XML ولا نستخدم apk.get_features()؟ لأنها تعيد الأسماء فقط بلا required.
"""
from __future__ import annotations

from lxml import etree

from .base import BaseAnalyzer
from .manifest_xml import attr, children, parse_bool

# فئات المواصفات -> بادئات أسماء الميزات الرسمية
CATEGORIES = {
    "camera": ("android.hardware.camera",),
    "microphone": ("android.hardware.microphone",),
    "gps": ("android.hardware.location.gps",),
    "location": ("android.hardware.location",),
    "bluetooth": ("android.hardware.bluetooth",),
    "nfc": ("android.hardware.nfc",),
    "wifi": ("android.hardware.wifi",),
    "accelerometer": ("android.hardware.sensor.accelerometer",),
    "gyroscope": ("android.hardware.sensor.gyroscope",),
    "sensors_other": ("android.hardware.sensor.",),
    "telephony": ("android.hardware.telephony",),
    "touchscreen": ("android.hardware.touchscreen", "android.hardware.faketouch"),
    "fingerprint": ("android.hardware.fingerprint", "android.hardware.biometrics"),
    "usb": ("android.hardware.usb",),
}


def _category(name: str) -> str:
    for cat, prefixes in CATEGORIES.items():
        if name.startswith(prefixes):
            return cat
    return "other"


def extract_features(manifest: etree._Element) -> dict:
    features, gles = [], None
    for el in children(manifest, "uses-feature"):
        name = attr(el, "name")
        required = parse_bool(attr(el, "required"))
        required = True if required is None else required  # القيمة الافتراضية في Android
        if name is None:
            gl = attr(el, "glEsVersion")  # وسم uses-feature بلا name يحدد إصدار OpenGL ES
            if gl:
                gles = {"version": gl, "required": required}
            continue
        features.append({"name": name, "required": required, "category": _category(name)})

    present = {}
    for f in features:
        present.setdefault(f["category"], []).append(f["name"])
    return {
        "features": features,
        "required": [f["name"] for f in features if f["required"]],
        "optional": [f["name"] for f in features if not f["required"]],
        "categories": {cat: cat in present for cat in CATEGORIES},
        "by_category": present,
        "gl_es_version": gles,
        "count": len(features),
    }


class HardwareAnalyzer(BaseAnalyzer):
    name = "hardware"

    def analyze(self, apk) -> dict:
        return extract_features(apk.apk.get_android_manifest_xml())
