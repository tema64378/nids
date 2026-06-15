"""Живой захват: scapy -> FlowTracker -> Predictor -> AlertEngine.

  sudo python -m capture.sniffer --iface en0

Захватывай трафик только в сетях, которыми владеешь или на мониторинг которых
у тебя есть явное разрешение.
"""

import time
import argparse

from scapy.all import sniff, IP, TCP, UDP

from features.extractor import FlowTracker
from model.predict import Predictor
from alerts.engine import AlertEngine


def run(iface, model_path, idle_timeout=15.0):
    tracker = FlowTracker(idle_timeout=idle_timeout)
    predictor = Predictor(model_path)
    alerts = AlertEngine()

    def handle(pkt):
        if IP not in pkt:
            return
        proto = pkt[IP].proto
        if TCP in pkt:
            sport, dport, flags = pkt[TCP].sport, pkt[TCP].dport, int(pkt[TCP].flags)
        elif UDP in pkt:
            sport, dport, flags = pkt[UDP].sport, pkt[UDP].dport, 0
        else:
            sport = dport = flags = 0
        tracker.update(pkt[IP].src, pkt[IP].dst, sport, dport, proto,
                       time.time(), len(pkt), flags)

    print(f"[*] Захват на {iface} (idle_timeout={idle_timeout}с). Ctrl-C чтобы остановить.")
    try:
        while True:
            # Ловим короткими сериями, затем прогоняем завершённые потоки через модель.
            sniff(iface=iface, prn=handle, store=False, timeout=2)
            for key, feats in tracker.expire():
                result = predictor.predict(feats)
                if result["is_attack"]:
                    proto, lo, hi = key
                    alerts.raise_alert(src=lo[0], dst=hi[0], result=result, features=feats)
    except KeyboardInterrupt:
        print("\n[*] Остановлено.")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--iface", required=True, help="Интерфейс, напр. en0 / eth0")
    ap.add_argument("--model", default="model/nids_model.pkl")
    ap.add_argument("--idle-timeout", type=float, default=15.0)
    args = ap.parse_args()
    run(args.iface, args.model, args.idle_timeout)


if __name__ == "__main__":
    main()
