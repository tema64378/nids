"""Канонический контракт признаков, общий для обучения, живого захвата и API.

Описание набора признаков в ОДНОМ месте не даёт train.py, predict.py, снифферу
и API незаметно разъехаться. Это расхождение (модель обучена на N признаках, а
обслуживает M) — самый частый баг в NIDS-демках.
"""

# Порядок важен: это точный порядок колонок, который модель ожидает везде.
FEATURES = [
    "flow_duration",        # секунды
    "total_fwd_packets",
    "total_bwd_packets",
    "total_fwd_bytes",
    "total_bwd_bytes",
    "fwd_pkt_len_mean",
    "bwd_pkt_len_mean",
    "flow_bytes_per_s",
    "flow_pkts_per_s",
    "flow_iat_mean",        # среднее время между пакетами, секунды
    "syn_flag_count",
    "rst_flag_count",
]

# Наши канонические имена -> имена колонок CICIDS-2017 (после str.strip()).
CICIDS_COLUMN_MAP = {
    "flow_duration":     "Flow Duration",                 # в датасете в микросекундах
    "total_fwd_packets": "Total Fwd Packets",
    "total_bwd_packets": "Total Backward Packets",
    "total_fwd_bytes":   "Total Length of Fwd Packets",
    "total_bwd_bytes":   "Total Length of Bwd Packets",
    "fwd_pkt_len_mean":  "Fwd Packet Length Mean",
    "bwd_pkt_len_mean":  "Bwd Packet Length Mean",
    "flow_bytes_per_s":  "Flow Bytes/s",
    "flow_pkts_per_s":   "Flow Packets/s",
    "flow_iat_mean":     "Flow IAT Mean",                  # в датасете в микросекундах
    "syn_flag_count":    "SYN Flag Count",
    "rst_flag_count":    "RST Flag Count",
}

# В CICIDS-2017 эти признаки в микросекундах; живой захват — в секундах.
# train.py конвертирует их, чтобы модель видела единые единицы.
MICROSECOND_FEATURES = {"flow_duration", "flow_iat_mean"}

LABEL_COLUMN = "Label"  # after str.strip()
