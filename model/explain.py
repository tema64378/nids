"""Объяснение обученной модели.

  python -m model.explain                 # важности признаков (без доп. зависимостей)
  python -m model.explain --shap          # SHAP-график -> reports/shap_summary.png

SHAP показывает по каждому признаку, насколько сильно он толкает поток в сторону
«атаки» — куда богаче глобальных важностей и сильный сигнал зрелости в ML-security.
"""

import argparse

import numpy as np
import pandas as pd
import joblib

from features.schema import FEATURES


def importances(bundle):
    clf = bundle["model"]
    imp = pd.Series(clf.feature_importances_, index=FEATURES).sort_values(ascending=False)
    print("Важности признаков:\n")
    print(imp.to_string())


def shap_report(bundle, data_path=None, sample=2000, out="reports/shap_summary.png"):
    import os
    import shap
    import matplotlib
    matplotlib.use("Agg")
    import matplotlib.pyplot as plt

    clf = bundle["model"]
    scaler = bundle.get("scaler")

    # Берём выборку потоков для объяснения.
    if data_path:
        from model.train import load_cicids
        X, _ = load_cicids(data_path)
    else:
        from model.train import make_synthetic
        X, _ = make_synthetic(n=sample)
    X = X[FEATURES].sample(min(sample, len(X)), random_state=42).reset_index(drop=True)

    Xs = scaler.transform(X.to_numpy()) if scaler is not None else X.to_numpy()

    explainer = shap.TreeExplainer(clf)
    sv = explainer.shap_values(Xs)

    # Приводим вывод SHAP к форме (n_samples, n_features) для взгляда на «атаку»,
    # учитывая разные формы, которые возвращают разные версии shap/sklearn.
    sv = np.array(sv)
    if sv.ndim == 3:
        if sv.shape[-1] == len(FEATURES):       # (classes, n, features)
            sv = sv[1] if sv.shape[0] > 1 else sv[0]
        else:                                   # (n, features, classes)
            sv = sv[:, :, -1]

    os.makedirs(os.path.dirname(out), exist_ok=True)
    shap.summary_plot(sv, X, feature_names=FEATURES, show=False)
    plt.tight_layout()
    plt.savefig(out, dpi=120, bbox_inches="tight")
    plt.close()
    print(f"[+] SHAP-график сохранён -> {out}")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--model", default="model/nids_model.pkl")
    ap.add_argument("--shap", action="store_true", help="Сгенерировать SHAP-график")
    ap.add_argument("--data", help="Папка/CSV CICIDS для выборки под SHAP (опционально)")
    args = ap.parse_args()

    bundle = joblib.load(args.model)
    importances(bundle)
    if args.shap:
        shap_report(bundle, data_path=args.data)


if __name__ == "__main__":
    main()
