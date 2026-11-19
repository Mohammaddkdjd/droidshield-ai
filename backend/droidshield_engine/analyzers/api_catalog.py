"""
كتالوج الـ APIs الحساسة: أي class/method في Android أو Java يرتبط بعملية حساسة.

الصيغة: لكل فئة قائمة (descriptor الصنف، أسماء الـ methods أو None = كل methods الصنف).

مهم: وجود API حساس ليس دليلاً على أن التطبيق خبيث. تطبيق رسائل سليم يستدعي
SmsManager.sendTextMessage، ومعظم التطبيقات تستخدم Reflection و Crypto عبر مكتباتها.
هذه معلومات وصفية للتحليل والشرح (XAI) لاحقاً.
"""
from __future__ import annotations

ALL = None

SENSITIVE_APIS: dict[str, list[tuple[str, frozenset[str] | None]]] = {
    "sms": [
        ("Landroid/telephony/SmsManager;", frozenset({
            "sendTextMessage", "sendMultipartTextMessage", "sendDataMessage", "divideMessage",
            "getDefault", "sendTextMessageWithoutPersisting"})),
        ("Landroid/telephony/gsm/SmsManager;", ALL),
        ("Landroid/telephony/SmsMessage;", frozenset({"createFromPdu", "getMessageBody",
                                                      "getOriginatingAddress", "getDisplayMessageBody"})),
        ("Landroid/provider/Telephony$Sms$Intents;", frozenset({"getMessagesFromIntent"})),
    ],
    "phone": [
        ("Landroid/telephony/TelephonyManager;", frozenset({
            "getDeviceId", "getImei", "getMeid", "getSubscriberId", "getSimSerialNumber",
            "getLine1Number", "getVoiceMailNumber", "getNetworkOperator", "getNetworkOperatorName",
            "getSimOperator", "getSimOperatorName", "getSimCountryIso", "getCallState", "listen",
            "getCellLocation", "getAllCellInfo", "getDeviceSoftwareVersion", "registerTelephonyCallback"})),
        ("Landroid/telecom/TelecomManager;", frozenset({"placeCall", "endCall", "acceptRingingCall",
                                                        "getCallCapablePhoneAccounts"})),
        ("Landroid/provider/CallLog$Calls;", ALL),
    ],
    "contacts": [
        ("Landroid/provider/ContactsContract$Contacts;", ALL),
        ("Landroid/provider/ContactsContract$CommonDataKinds$Phone;", ALL),
        ("Landroid/provider/ContactsContract$Data;", ALL),
        ("Landroid/provider/ContactsContract$RawContacts;", ALL),
        ("Landroid/accounts/AccountManager;", frozenset({"getAccounts", "getAccountsByType",
                                                         "getPassword", "getAuthToken", "addAccountExplicitly"})),
    ],
    "location": [
        ("Landroid/location/LocationManager;", frozenset({
            "requestLocationUpdates", "getLastKnownLocation", "requestSingleUpdate",
            "getCurrentLocation", "addGpsStatusListener", "registerGnssStatusCallback"})),
        ("Lcom/google/android/gms/location/FusedLocationProviderClient;", frozenset({
            "getLastLocation", "requestLocationUpdates", "getCurrentLocation"})),
        ("Landroid/net/wifi/WifiManager;", frozenset({"getScanResults", "startScan"})),
    ],
    "camera": [
        ("Landroid/hardware/Camera;", frozenset({"open", "takePicture", "startPreview"})),
        ("Landroid/hardware/camera2/CameraManager;", frozenset({"openCamera"})),
        ("Landroid/hardware/camera2/CameraDevice;", frozenset({"createCaptureSession", "createCaptureRequest"})),
    ],
    "microphone": [
        ("Landroid/media/MediaRecorder;", frozenset({"setAudioSource", "start"})),
        ("Landroid/media/AudioRecord;", frozenset({"<init>", "startRecording"})),
    ],
    "network": [
        ("Ljava/net/URL;", frozenset({"openConnection", "openStream"})),
        ("Ljava/net/HttpURLConnection;", frozenset({"connect", "getInputStream", "getOutputStream"})),
        ("Ljavax/net/ssl/HttpsURLConnection;", frozenset({"connect", "setHostnameVerifier",
                                                          "setSSLSocketFactory", "setDefaultHostnameVerifier"})),
        ("Ljava/net/Socket;", frozenset({"<init>", "connect"})),
        ("Ljava/net/DatagramSocket;", frozenset({"<init>", "send"})),
        ("Lokhttp3/OkHttpClient;", frozenset({"newCall"})),
        ("Lorg/apache/http/impl/client/DefaultHttpClient;", frozenset({"execute", "<init>"})),
        ("Landroid/webkit/WebView;", frozenset({"loadUrl", "loadData", "addJavascriptInterface",
                                                "evaluateJavascript", "postUrl"})),
    ],
    "file_system": [
        ("Ljava/io/FileOutputStream;", frozenset({"<init>"})),
        ("Ljava/io/File;", frozenset({"delete", "createTempFile", "setExecutable", "listFiles"})),
        ("Ljava/io/RandomAccessFile;", frozenset({"<init>"})),
        ("Landroid/os/Environment;", frozenset({"getExternalStorageDirectory",
                                                "getExternalStoragePublicDirectory"})),
    ],
    "reflection": [
        ("Ljava/lang/Class;", frozenset({"forName", "getMethod", "getDeclaredMethod", "getField",
                                         "getDeclaredField", "newInstance", "getDeclaredConstructor"})),
        ("Ljava/lang/reflect/Method;", frozenset({"invoke"})),
        ("Ljava/lang/reflect/Field;", frozenset({"set", "get", "setAccessible"})),
        ("Ljava/lang/reflect/Constructor;", frozenset({"newInstance"})),
        ("Ljava/lang/reflect/AccessibleObject;", frozenset({"setAccessible"})),
    ],
    "dynamic_code_loading": [
        ("Ldalvik/system/DexClassLoader;", frozenset({"<init>"})),
        ("Ldalvik/system/PathClassLoader;", frozenset({"<init>"})),
        ("Ldalvik/system/InMemoryDexClassLoader;", frozenset({"<init>"})),
        ("Ldalvik/system/BaseDexClassLoader;", frozenset({"<init>"})),
        ("Ldalvik/system/DexFile;", frozenset({"loadDex", "<init>", "loadClass"})),
        ("Ljava/lang/ClassLoader;", frozenset({"loadClass"})),
        ("Ljava/lang/System;", frozenset({"load", "loadLibrary"})),
        ("Ljava/lang/Runtime;", frozenset({"load", "loadLibrary"})),
    ],
    "cryptography": [
        ("Ljavax/crypto/Cipher;", frozenset({"getInstance", "init", "doFinal"})),
        ("Ljavax/crypto/spec/SecretKeySpec;", frozenset({"<init>"})),
        ("Ljavax/crypto/spec/IvParameterSpec;", frozenset({"<init>"})),
        ("Ljavax/crypto/Mac;", frozenset({"getInstance"})),
        ("Ljavax/crypto/KeyGenerator;", frozenset({"getInstance"})),
        ("Ljava/security/MessageDigest;", frozenset({"getInstance"})),
        ("Landroid/util/Base64;", frozenset({"decode", "encode", "encodeToString"})),
    ],
    "process_execution": [
        ("Ljava/lang/Runtime;", frozenset({"exec"})),
        ("Ljava/lang/ProcessBuilder;", frozenset({"<init>", "start", "command"})),
    ],
    "device_admin": [
        ("Landroid/app/admin/DevicePolicyManager;", ALL),
    ],
    "accessibility": [
        ("Landroid/accessibilityservice/AccessibilityService;", frozenset({
            "performGlobalAction", "getRootInActiveWindow", "dispatchGesture", "takeScreenshot"})),
        ("Landroid/view/accessibility/AccessibilityNodeInfo;", frozenset({"performAction", "getText",
                                                                         "findAccessibilityNodeInfosByViewId"})),
        ("Landroid/view/accessibility/AccessibilityManager;", frozenset({"getEnabledAccessibilityServiceList",
                                                                         "isEnabled"})),
    ],
    "package_management": [
        ("Landroid/content/pm/PackageManager;", frozenset({
            "getInstalledPackages", "getInstalledApplications", "setComponentEnabledSetting",
            "queryIntentActivities", "getLaunchIntentForPackage", "setApplicationEnabledSetting"})),
        ("Landroid/content/pm/PackageInstaller;", frozenset({"createSession", "openSession", "uninstall"})),
    ],
    # فئات إضافية شائعة في البرمجيات الخبيثة الحديثة (خارج القائمة الأساسية في المواصفات)
    "screen_capture": [
        ("Landroid/media/projection/MediaProjectionManager;", frozenset({"createScreenCaptureIntent",
                                                                         "getMediaProjection"})),
    ],
    "overlay": [
        ("Landroid/view/WindowManager;", frozenset({"addView"})),
    ],
    "clipboard": [
        ("Landroid/content/ClipboardManager;", frozenset({"getPrimaryClip", "setPrimaryClip",
                                                          "addPrimaryClipChangedListener"})),
    ],
}


def build_index() -> dict[str, list[tuple[str, frozenset[str] | None]]]:
    """class descriptor -> [(category, methods)]. صنف واحد قد يتبع أكثر من فئة (مثل Runtime)."""
    index: dict[str, list] = {}
    for category, rules in SENSITIVE_APIS.items():
        for cls, methods in rules:
            index.setdefault(cls, []).append((category, methods))
    return index


def match(index: dict, class_desc: str, method: str) -> str | None:
    for category, methods in index.get(class_desc, ()):
        if methods is None or method in methods:
            return category
    return None
