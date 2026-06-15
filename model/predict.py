"""Обёртка инференса. Загружает бандл (модель + scaler + метаданные) и
превращает словарь признаков в предсказание. Работает и для бинарной,
и для мультикласс-модели."""

import numpy as np
import joblib

from features.schema import FEATURES


class Predictor:
    def __init__(self, model_path="model/nids_model.pkl"):
        bundle = joblib.load(model_path)
        self.model = bundle["model"]
        self.scaler = bundle.get("scaler")
        self.classes = bundle.get("classes")  # список имён классов, если мультикласс

    def _vector(self, features: dict):
        return np.array([[float(features.get(f, 0.0)) for f in FEATURES]])

    def predict(self, features: dict):
        X = self._vector(features)
        if self.scaler is not None:
            X = self.scaler.transform(X)
        proba = self.model.predict_proba(X)[0]

        if self.classes is not None:
            # Мультикласс: имя класса берём из класса с максимальной вероятностью.
            idx = int(np.argmax(proba))
            label = str(self.classes[idx])
            is_attack = label.upper() != "BENIGN"
            confidence = float(proba[idx])
        else:
            # Бинарная: класс 1 == атака.
            is_attack = bool(self.model.predict(X)[0])
            confidence = float(proba[1]) if len(proba) > 1 else float(proba[0])
            label = "ATTACK" if is_attack else "NORMAL"

        return {
            "is_attack": is_attack,
            "label": label,
            "confidence": round(confidence, 3),
        }
