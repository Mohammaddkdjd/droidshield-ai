"""
تحليل المكتبات الأصلية (Native Libraries, .so) دون تشغيلها.

ما هي؟ كود C/C++ مترجم لمعالج معيّن، بصيغة ELF، موجود في lib/<ABI>/libname.so.
    ABI (Application Binary Interface) = معمارية المعالج:
        armeabi-v7a (ARM 32) | arm64-v8a (ARM 64) | x86 | x86_64 | (قديم: armeabi, mips)

نستخدم pyelftools لقراءة بنية ELF فقط (Pure Python، لا ينفّذ أي كود). نستخرج:
    - معلومات الـ header: 32/64 bit، المعالج، النوع
    - DT_NEEDED: المكتبات التي تعتمد عليها، و SONAME
    - Exported symbols: الدوال المتاحة للخارج، ومنها JNI (Java_* و JNI_OnLoad) التي تربط
      native methods في كود Java بهذه المكتبة
    - Imported symbols حساسة (execve, ptrace, dlopen...): معلومة وصفية لا دليل خبث

مؤشرات غير طبيعية نرصدها:
    - ملف .so ليس ELF أصلاً (ملف مموّه)
    - معالج ELF لا يطابق مجلد الـ ABI (مكتبة x86 داخل arm64-v8a)
    - ملفات .so خارج lib/ (Android لا يحمّلها تلقائياً؛ تُحمَّل يدوياً عادة)
"""
from __future__ import annotations

import hashlib
import io
import re

from elftools.elf.dynamic import DynamicSection
from elftools.elf.elffile import ELFFile
from elftools.elf.sections import SymbolTableSection

from ..config import DEFAULT_CONTENT_LIMITS, ContentLimits
from .base import BaseAnalyzer

LIB_RE = re.compile(r"^lib/([^/]+)/([^/]+\.so)$")
ABI_ARCH = {"armeabi": "ARM", "armeabi-v7a": "ARM", "arm64-v8a": "ARM64", "x86": "x86", "x86_64": "x86_64",
            "mips": "MIPS", "mips64": "MIPS64"}
MACHINE_ABI = {"EM_ARM": {"armeabi", "armeabi-v7a"}, "EM_AARCH64": {"arm64-v8a"}, "EM_386": {"x86"},
               "EM_X86_64": {"x86_64"}, "EM_MIPS": {"mips", "mips64"}}
SENSITIVE_IMPORTS = {"system", "execve", "execl", "execlp", "execv", "execvp", "fork", "popen", "ptrace",
                     "dlopen", "dlsym", "mprotect", "inotify_add_watch", "__system_property_get", "kill",
                     "socket", "connect"}


def analyze_elf(data: bytes, max_symbols: int) -> dict:
    elf = ELFFile(io.BytesIO(data))
    info = {
        "class": f"ELF{elf.elfclass}",
        "machine": elf["e_machine"],
        "endianness": "little" if elf.little_endian else "big",
        "type": elf["e_type"],
        "sections": [s.name for s in elf.iter_sections() if s.name],
        "stripped": elf.get_section_by_name(".symtab") is None,
        "needed": [], "soname": None,
        "exported": [], "exported_count": 0, "jni_functions": [],
        "imported_sensitive": [], "imported_count": 0,
    }
    for sec in elf.iter_sections():
        if isinstance(sec, DynamicSection):
            for tag in sec.iter_tags():
                if tag.entry.d_tag == "DT_NEEDED":
                    info["needed"].append(tag.needed)
                elif tag.entry.d_tag == "DT_SONAME":
                    info["soname"] = tag.soname
    dynsym = elf.get_section_by_name(".dynsym")
    if isinstance(dynsym, SymbolTableSection):
        for sym in dynsym.iter_symbols():
            name = sym.name
            if not name:
                continue
            if sym["st_shndx"] == "SHN_UNDEF":
                info["imported_count"] += 1
                if name in SENSITIVE_IMPORTS:
                    info["imported_sensitive"].append(name)
            elif sym["st_info"]["bind"] in ("STB_GLOBAL", "STB_WEAK") and \
                    sym["st_info"]["type"] in ("STT_FUNC", "STT_OBJECT"):
                info["exported_count"] += 1
                if name.startswith("Java_") or name in ("JNI_OnLoad", "JNI_OnUnload"):
                    info["jni_functions"].append(name)
                if len(info["exported"]) < max_symbols:
                    info["exported"].append(name)
    info["imported_sensitive"] = sorted(set(info["imported_sensitive"]))
    info["jni_functions"] = info["jni_functions"][:max_symbols]
    return info


class NativeAnalyzer(BaseAnalyzer):
    name = "native"

    def __init__(self, limits: ContentLimits = DEFAULT_CONTENT_LIMITS):
        self.limits = limits

    def analyze(self, apk) -> dict:
        libs, outside = [], []
        for name, entry in sorted(apk.zip.entries.items()):
            m = LIB_RE.match(name)
            if not m:
                if name.lower().endswith(".so"):
                    outside.append(name)
                continue
            abi, lib_name = m.groups()
            item = {"path": name, "abi": abi, "arch": ABI_ARCH.get(abi, "unknown"), "name": lib_name,
                    "size": entry.declared_size, "sha256": None, "elf": None, "error": None, "abi_mismatch": False}
            try:
                data = apk.read_entry(name, self.limits.max_native_lib_size)
                item["size"] = len(data)
                item["sha256"] = hashlib.sha256(data).hexdigest()
                if data[:4] != b"\x7fELF":
                    item["error"] = "ليس ملف ELF (ملف مموّه بامتداد .so)"
                else:
                    item["elf"] = analyze_elf(data, self.limits.max_symbols_listed)
                    expected = MACHINE_ABI.get(item["elf"]["machine"])
                    item["abi_mismatch"] = expected is not None and abi not in expected
            except Exception as e:
                item["error"] = f"{type(e).__name__}: {e}"
            libs.append(item)

        abis = sorted({lib["abi"] for lib in libs})
        return {
            "libraries": libs,
            "count": len(libs),
            "unique_names": sorted({lib["name"] for lib in libs}),
            "abis": abis,
            "architectures": sorted({ABI_ARCH.get(a, "unknown") for a in abis}),
            "jni_functions": sorted({j for lib in libs if lib["elf"] for j in lib["elf"]["jni_functions"]}),
            "imported_sensitive": sorted({s for lib in libs if lib["elf"] for s in lib["elf"]["imported_sensitive"]}),
            "not_elf": [lib["path"] for lib in libs if lib["error"] and "ELF" in lib["error"]],
            "abi_mismatches": [lib["path"] for lib in libs if lib["abi_mismatch"]],
            "so_outside_lib": outside,
        }
