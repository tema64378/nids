"""Движок алертов: порог уверенности -> консоль + JSONL-лог + опционально Telegram.

JSONL-лог (data/alerts.jsonl) читает дашборд на Streamlit, поэтому для демо
обходимся без базы данных.
"""

import os
import json
import time
import urllib.parse
import urllib.request


class AlertEngine:
    def __init__(self, log_file=None):
        self.tg_token = os.getenv("TELEGRAM_BOT_TOKEN")
        self.tg_chat = os.getenv("TELEGRAM_CHAT_ID")
        self.min_confidence = float(os.getenv("ALERT_MIN_CONFIDENCE", "0.8"))
        self.log_file = log_file or os.getenv("ALERTS_FILE", "data/alerts.jsonl")

    def raise_alert(self, src, dst, result, features):
        if result["confidence"] < self.min_confidence:
            return

        record = {
            "ts": time.time(),
            "label": result["label"],
            "confidence": result["confidence"],
            "src": src,
            "dst": dst,
            "packets": features["total_fwd_packets"] + features["total_bwd_packets"],
        }
        self._log(record)
        self._console(record)
        self._telegram(record)

    def _console(self, r):
        print(
            f"🚨 АЛЕРТ  {r['label']}  уверенность={r['confidence']}  "
            f"{r['src']} -> {r['dst']}  пакетов={r['packets']}"
        )

    def _log(self, record):
        os.makedirs(os.path.dirname(self.log_file), exist_ok=True)
        with open(self.log_file, "a") as f:
            f.write(json.dumps(record) + "\n")

    def _telegram(self, r):
        if not (self.tg_token and self.tg_chat):
            return
        text = (
            f"🚨 АЛЕРТ NIDS\n"
            f"Тип: {r['label']}\n"
            f"Уверенность: {r['confidence']}\n"
            f"Источник: {r['src']}\n"
            f"Назначение: {r['dst']}\n"
            f"Пакетов: {r['packets']}\n"
            f"Время: {time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(r['ts']))}"
        )
        url = f"https://api.telegram.org/bot{self.tg_token}/sendMessage"
        data = urllib.parse.urlencode({"chat_id": self.tg_chat, "text": text}).encode()
        try:
            urllib.request.urlopen(url, data=data, timeout=5)
        except Exception as e:  # noqa: BLE001 - алертинг не должен ронять захват
            print(f"[!] Не удалось отправить в Telegram: {e}")
