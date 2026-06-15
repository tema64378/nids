"""Группирует пакеты в двунаправленные потоки и считает признаки в стиле CICIDS.

В исходном плане пакеты вечно добавлялись в dict и признаки не отдавались.
Здесь потоки ключуются каноническим 5-кортежем (оба направления делят ключ) и
завершаются по простою, после чего отдаётся вектор признаков.
"""

import time

# Биты TCP-флагов
FIN = 0x01
SYN = 0x02
RST = 0x04


class Flow:
    def __init__(self, key, first_src):
        self.key = key
        self.first_src = first_src      # задаёт «прямое» (forward) направление
        self.start = None
        self.last = None
        self.fwd_lens = []
        self.bwd_lens = []
        self.timestamps = []
        self.syn = 0
        self.rst = 0
        self.fin = 0

    def add(self, ts, src, length, flags):
        if self.start is None:
            self.start = ts
        self.last = ts
        self.timestamps.append(ts)
        if src == self.first_src:
            self.fwd_lens.append(length)
        else:
            self.bwd_lens.append(length)
        if flags & SYN:
            self.syn += 1
        if flags & RST:
            self.rst += 1
        if flags & FIN:
            self.fin += 1

    def duration(self):
        if self.start is None:
            return 0.0
        return self.last - self.start

    def features(self):
        dur = self.duration()
        all_lens = self.fwd_lens + self.bwd_lens
        n_pkts = len(all_lens)
        total_bytes = sum(all_lens)
        iats = [b - a for a, b in zip(self.timestamps, self.timestamps[1:])]
        iat_mean = (sum(iats) / len(iats)) if iats else 0.0
        return {
            "flow_duration": dur,
            "total_fwd_packets": len(self.fwd_lens),
            "total_bwd_packets": len(self.bwd_lens),
            "total_fwd_bytes": sum(self.fwd_lens),
            "total_bwd_bytes": sum(self.bwd_lens),
            "fwd_pkt_len_mean": (sum(self.fwd_lens) / len(self.fwd_lens)) if self.fwd_lens else 0.0,
            "bwd_pkt_len_mean": (sum(self.bwd_lens) / len(self.bwd_lens)) if self.bwd_lens else 0.0,
            "flow_bytes_per_s": (total_bytes / dur) if dur > 0 else float(total_bytes),
            "flow_pkts_per_s": (n_pkts / dur) if dur > 0 else float(n_pkts),
            "flow_iat_mean": iat_mean,
            "syn_flag_count": self.syn,
            "rst_flag_count": self.rst,
        }


class FlowTracker:
    """Отслеживает активные потоки и завершает простаивающие в векторы признаков."""

    def __init__(self, idle_timeout=15.0):
        self.idle_timeout = idle_timeout
        self.flows = {}

    @staticmethod
    def _key(src, dst, sport, dport, proto):
        # Канонический ключ: упорядочиваем две конечные точки, чтобы оба
        # направления схлопывались в один двунаправленный поток.
        a = (src, sport)
        b = (dst, dport)
        lo, hi = sorted([a, b])
        return (proto, lo, hi)

    def update(self, src, dst, sport, dport, proto, ts, length, flags):
        key = self._key(src, dst, sport, dport, proto)
        flow = self.flows.get(key)
        if flow is None:
            flow = Flow(key, first_src=src)
            self.flows[key] = flow
        flow.add(ts, src, length, flags)
        return key

    def expire(self, now=None):
        """Возвращает [(key, features_dict)] для потоков, простоявших дольше таймаута."""
        now = now or time.time()
        done = []
        for key, flow in list(self.flows.items()):
            if flow.last is not None and (now - flow.last) > self.idle_timeout:
                done.append((key, flow.features()))
                del self.flows[key]
        return done
