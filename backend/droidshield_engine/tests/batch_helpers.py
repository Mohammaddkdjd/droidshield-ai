"""
عمّال وهميون لاختبار الـ Batch (يجب أن يكونوا في ملف مستقل قابل للاستيراد، لأن نمط spawn
يستورد دالة العامل من جديد داخل الـ process الجديد).
"""
import os
import time


def hanging_worker(path, results_dir, log_dir, conn):
    """يحاكي ملفاً يُعلق المحلل (حلقة لا نهائية في parser)."""
    time.sleep(3600)


def crashing_worker(path, results_dir, log_dir, conn):
    """يحاكي انهياراً قاتلاً (مثل segfault في مكتبة native) دون إرسال نتيجة."""
    os._exit(3)
