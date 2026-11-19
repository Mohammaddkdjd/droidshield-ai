"""
ميزانية زمنية تعاونية (cooperative time budget) للوحدات الثقيلة.

لماذا ليست timeout بالقوة؟
    Python لا يستطيع إيقاف thread من الخارج بأمان. بدلاً من ذلك تسأل الحلقة الثقيلة
    budget.exceeded() كل فترة، فتتوقف بنفسها وتعيد ما جمعته مع علامة truncated.
    الحد الصارم (قتل عملية عالقة بالكامل) يطبقه محرك الـ Batch على مستوى الـ process.
"""
from __future__ import annotations

import time


class TimeBudget:
    def __init__(self, seconds: float):
        self.seconds = seconds
        self.start = time.monotonic()
        self.hit = False

    def exceeded(self) -> bool:
        if not self.hit and time.monotonic() - self.start > self.seconds:
            self.hit = True
        return self.hit

    @property
    def elapsed(self) -> float:
        return round(time.monotonic() - self.start, 3)
