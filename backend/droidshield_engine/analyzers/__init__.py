"""وحدات التحليل الثابت (Full Static Analysis). كل وحدة مستقلة وتعيد dict قابلاً لـ JSON."""
from .api_analyzer import ApiAnalyzer
from .base import BaseAnalyzer
from .certificate_analyzer import CertificateAnalyzer
from .component_analyzer import ComponentAnalyzer
from .dex_analyzer import DexAnalyzer
from .hardware_analyzer import HardwareAnalyzer
from .manifest_analyzer import ManifestAnalyzer
from .metadata_analyzer import MetadataAnalyzer
from .native_analyzer import NativeAnalyzer
from .network_analyzer import NetworkAnalyzer
from .permission_analyzer import PermissionAnalyzer
from .resources_analyzer import ResourcesAnalyzer
from .strings_analyzer import StringsAnalyzer

__all__ = [
    "BaseAnalyzer", "MetadataAnalyzer", "ManifestAnalyzer", "PermissionAnalyzer", "ComponentAnalyzer",
    "HardwareAnalyzer", "DexAnalyzer", "ApiAnalyzer", "ResourcesAnalyzer", "StringsAnalyzer",
    "NetworkAnalyzer", "NativeAnalyzer", "CertificateAnalyzer",
]
