"""Обучение классификатора NIDS.

  python -m model.train                      # синтетика, запускается мгновенно
  python -m model.train --data data/cicids   # обучение на CSV из CICIDS-2017
  python -m model.train --data ... --multiclass   # предсказывать ТИП атаки

Встроен генератор синтетики, чтобы весь пайплайн был запускаем ещё до того,
как ты скачаешь 8-гигабайтный датасет CICIDS-2017.
"""

import os
import glob
import argparse

import numpy as np
import pandas as pd
import joblib
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler
from sklearn.metrics import (
    classification_report,
    confusion_matrix,
    ConfusionMatrixDisplay,
    RocCurveDisplay,
)

from features.schema import (
    FEATURES,
    CICIDS_COLUMN_MAP,
    MICROSECOND_FEATURES,
    LABEL_COLUMN,
)


def normalize_label(label):
    """Схлопывает детальные метки CICIDS-2017 в семейства атак.

    В сыром датасете метки вида 'DoS Hulk', 'DoS GoldenEye', 'Web Attack – XSS',
    'FTP-Patator' (со странными юникод-тире). Группировка даёт чистые,
    обучаемые классы. На синтетических метках тоже работает безопасно.
    """
    l = str(label).strip().upper()
    if l == "BENIGN":
        return "BENIGN"
    if "DDOS" in l:
        return "DDoS"
    if l.startswith("DOS"):
        return "DoS"
    if "PORTSCAN" in l:
        return "PortScan"
    if "PATATOR" in l:
        return "BruteForce"
    if "WEB ATTACK" in l:
        return "WebAttack"
    if "BOT" in l:
        return "Bot"
    if "INFILTRATION" in l:
        return "Infiltration"
    if "HEARTBLEED" in l:
        return "Heartbleed"
    return str(label).strip()


def save_plots(clf, y_test, y_pred, Xte, multiclass, out_dir="reports"):
    """Сохраняет матрицу ошибок (всегда) и ROC-кривую (для бинарной) в отчёт."""
    import matplotlib
    matplotlib.use("Agg")
    import matplotlib.pyplot as plt

    os.makedirs(out_dir, exist_ok=True)

    ConfusionMatrixDisplay.from_predictions(y_test, y_pred, xticks_rotation=45)
    plt.title("Матрица ошибок")
    plt.tight_layout()
    plt.savefig(os.path.join(out_dir, "confusion_matrix.png"), dpi=120)
    plt.close()

    if not multiclass:
        RocCurveDisplay.from_estimator(clf, Xte, y_test)
        plt.title("ROC curve")
        plt.tight_layout()
        plt.savefig(os.path.join(out_dir, "roc_curve.png"), dpi=120)
        plt.close()
        print(f"[+] Сохранено: reports/confusion_matrix.png и reports/roc_curve.png")
    else:
        print(f"[+] Сохранено: reports/confusion_matrix.png "
              f"(ROC только для бинарной; для мультикласса пропущена)")


def load_cicids(path):
    """Загружает один CSV или папку с CSV, возвращает (X[FEATURES], y_raw)."""
    files = glob.glob(os.path.join(path, "*.csv")) if os.path.isdir(path) else [path]
    if not files:
        raise FileNotFoundError(f"CSV-файлы не найдены в {path}")

    rename = {v: k for k, v in CICIDS_COLUMN_MAP.items()}
    frames = []
    for f in files:
        df = pd.read_csv(f, low_memory=False)
        df.columns = df.columns.str.strip()
        df = df.rename(columns=rename)
        frames.append(df)
    data = pd.concat(frames, ignore_index=True)
    data = data.replace([np.inf, -np.inf], 0).fillna(0)

    y_raw = data[LABEL_COLUMN].astype(str).str.strip()

    # Исправление единиц: CICIDS хранит часть временных признаков в микросекундах.
    for col in MICROSECOND_FEATURES:
        if col in data.columns:
            data[col] = data[col] / 1_000_000.0

    X = pd.DataFrame({c: (data[c] if c in data.columns else 0.0) for c in FEATURES})
    return X[FEATURES], y_raw


def make_synthetic(n=30000, seed=42):
    """Игрушечный датасет с тремя типами поведения — для демо и бинарной, и мультикласс."""
    rng = np.random.default_rng(seed)
    feats = {f: np.zeros(n) for f in FEATURES}
    labels = np.empty(n, dtype=object)
    roll = rng.random(n)

    for i in range(n):
        r = roll[i]
        if r < 0.6:                       # норма: сбалансированные, более долгие потоки
            labels[i] = "BENIGN"
            dur = rng.uniform(0.5, 30)
            fwd, bwd = rng.integers(5, 60), rng.integers(5, 60)
            fwd_len, bwd_len = rng.uniform(200, 800), rng.uniform(200, 1200)
            syn, rst = rng.integers(0, 2), rng.integers(0, 1)
        elif r < 0.8:                     # скан портов: много мелких пакетов с SYN
            labels[i] = "PortScan"
            dur = rng.uniform(0, 0.3)
            fwd, bwd = rng.integers(30, 300), rng.integers(0, 3)
            fwd_len, bwd_len = rng.uniform(40, 80), rng.uniform(0, 60)
            syn, rst = rng.integers(20, 200), rng.integers(0, 30)
        else:                            # DoS: огромный объём fwd, короткая длительность
            labels[i] = "DoS"
            dur = rng.uniform(0, 2)
            fwd, bwd = rng.integers(200, 2000), rng.integers(0, 50)
            fwd_len, bwd_len = rng.uniform(60, 200), rng.uniform(0, 120)
            syn, rst = rng.integers(50, 800), rng.integers(0, 100)

        total_fwd_bytes = fwd * fwd_len
        total_bwd_bytes = bwd * bwd_len
        total_pkts = fwd + bwd
        total_bytes = total_fwd_bytes + total_bwd_bytes

        feats["flow_duration"][i] = dur
        feats["total_fwd_packets"][i] = fwd
        feats["total_bwd_packets"][i] = bwd
        feats["total_fwd_bytes"][i] = total_fwd_bytes
        feats["total_bwd_bytes"][i] = total_bwd_bytes
        feats["fwd_pkt_len_mean"][i] = fwd_len
        feats["bwd_pkt_len_mean"][i] = bwd_len
        feats["flow_bytes_per_s"][i] = total_bytes / dur if dur > 0 else total_bytes
        feats["flow_pkts_per_s"][i] = total_pkts / dur if dur > 0 else total_pkts
        feats["flow_iat_mean"][i] = dur / total_pkts if total_pkts else 0.0
        feats["syn_flag_count"][i] = syn
        feats["rst_flag_count"][i] = rst

    return pd.DataFrame(feats)[FEATURES], pd.Series(labels)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--data", help="CSV-файл или папка с CICIDS-2017")
    ap.add_argument("--multiclass", action="store_true",
                    help="Предсказывать тип атаки вместо атака/норма")
    ap.add_argument("--out", default="model/nids_model.pkl")
    ap.add_argument("--no-plots", action="store_true", help="Не сохранять графики отчёта")
    args = ap.parse_args()

    if args.data:
        print(f"[*] Загружаю CICIDS-2017 из {args.data}")
        X, y_raw = load_cicids(args.data)
    else:
        print("[!] --data не задан -> генерирую синтетический датасет (запускаемое демо).")
        X, y_raw = make_synthetic()

    # Схлопываем детальные метки CICIDS в семейства атак.
    y_raw = y_raw.map(normalize_label)

    if args.multiclass:
        y = y_raw
        print(f"[*] Классы: {sorted(y.unique())}")
    else:
        y = (y_raw.str.upper() != "BENIGN").astype(int)

    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.2, random_state=42, stratify=y)

    # Обучаем scaler на массивах numpy (не DataFrame), чтобы он не хранил имена
    # признаков; живой инференс подаёт обычные numpy-векторы и иначе будет ругаться.
    scaler = StandardScaler().fit(X_train.to_numpy())
    Xtr, Xte = scaler.transform(X_train.to_numpy()), scaler.transform(X_test.to_numpy())

    clf = RandomForestClassifier(
        n_estimators=150, n_jobs=-1, random_state=42, class_weight="balanced")
    clf.fit(Xtr, y_train)

    y_pred = clf.predict(Xte)
    print("\n=== отчёт по классификации ===")
    print(classification_report(y_test, y_pred))
    print("=== матрица ошибок ===")
    print(confusion_matrix(y_test, y_pred))

    if not args.no_plots:
        save_plots(clf, y_test, y_pred, Xte, args.multiclass)

    bundle = {
        "model": clf,
        "scaler": scaler,
        "features": FEATURES,
        "classes": list(clf.classes_) if args.multiclass else None,
    }
    os.makedirs(os.path.dirname(args.out), exist_ok=True)
    joblib.dump(bundle, args.out)
    print(f"\n[+] Модель сохранена -> {args.out}")


if __name__ == "__main__":
    main()
