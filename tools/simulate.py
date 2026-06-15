"""Прогоняет синтетические потоки через реальную модель + движок алертов.

Позволяет смотреть, как дашборд наполняется живыми алертами, без реального
атакующего трафика в твоей сети.

  python -m tools.simulate            # непрерывный поток (Ctrl-C чтобы остановить)
  python -m tools.simulate --once     # один батч
  python -m tools.simulate --interval 0.5

Совет: сначала обучи мультикласс-модель (python -m model.train --multiclass),
чтобы в алертах были ТИПЫ атак (PortScan / DoS), а не просто ATTACK.
"""

import time
import random
import argparse

from model.predict import Predictor
from alerts.engine import AlertEngine


def _rand_ip():
    return f"192.168.{random.randint(0, 5)}.{random.randint(1, 254)}"


def _finish(f):
    """Заполняет производные поля (байты/скорости) из счётчиков пакетов."""
    f["total_fwd_bytes"] = f["total_fwd_packets"] * f["fwd_pkt_len_mean"]
    f["total_bwd_bytes"] = f["total_bwd_packets"] * f["bwd_pkt_len_mean"]
    total_pkts = f["total_fwd_packets"] + f["total_bwd_packets"]
    total_bytes = f["total_fwd_bytes"] + f["total_bwd_bytes"]
    dur = f["flow_duration"]
    f["flow_bytes_per_s"] = total_bytes / dur if dur > 0 else total_bytes
    f["flow_pkts_per_s"] = total_pkts / dur if dur > 0 else total_pkts
    f["flow_iat_mean"] = dur / total_pkts if total_pkts else 0.0
    return f


def port_scan():
    return _finish({
        "flow_duration": random.uniform(0.0, 0.3),
        "total_fwd_packets": random.randint(30, 300),
        "total_bwd_packets": random.randint(0, 3),
        "fwd_pkt_len_mean": random.uniform(40, 80),
        "bwd_pkt_len_mean": random.uniform(0, 60),
        "syn_flag_count": random.randint(20, 200),
        "rst_flag_count": random.randint(0, 30),
    })


def dos():
    return _finish({
        "flow_duration": random.uniform(0.0, 2.0),
        "total_fwd_packets": random.randint(200, 2000),
        "total_bwd_packets": random.randint(0, 50),
        "fwd_pkt_len_mean": random.uniform(60, 200),
        "bwd_pkt_len_mean": random.uniform(0, 120),
        "syn_flag_count": random.randint(50, 800),
        "rst_flag_count": random.randint(0, 100),
    })


def benign():
    return _finish({
        "flow_duration": random.uniform(0.5, 30),
        "total_fwd_packets": random.randint(5, 60),
        "total_bwd_packets": random.randint(5, 60),
        "fwd_pkt_len_mean": random.uniform(200, 800),
        "bwd_pkt_len_mean": random.uniform(200, 1200),
        "syn_flag_count": random.randint(0, 1),
        "rst_flag_count": 0,
    })


def run(once, interval):
    predictor = Predictor()
    alerts = AlertEngine()
    generators = [port_scan, dos, benign, benign]  # ~50% нормального трафика

    print("[*] Симуляция трафика. Атаки пишутся в data/alerts.jsonl. Ctrl-C чтобы остановить.")
    try:
        while True:
            flow = random.choice(generators)()
            result = predictor.predict(flow)
            if result["is_attack"]:
                alerts.raise_alert(src=_rand_ip(), dst=_rand_ip(),
                                   result=result, features=flow)
            else:
                print(f"   нормальный поток (уверенность={result['confidence']}) — без алерта")
            if once:
                break
            time.sleep(interval)
    except KeyboardInterrupt:
        print("\n[*] Остановлено.")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--once", action="store_true")
    ap.add_argument("--interval", type=float, default=1.0)
    args = ap.parse_args()
    run(args.once, args.interval)


if __name__ == "__main__":
    main()
