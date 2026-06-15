"""Эндпоинт инференса на FastAPI.

Поля модели запроса — ровно FEATURES, поэтому API не может разъехаться с тем,
на чём обучалась модель.

  uvicorn api.main:app
"""

from fastapi import FastAPI
from pydantic import BaseModel

from model.predict import Predictor
from features.schema import FEATURES

app = FastAPI(title="NIDS API", version="1.0")
predictor = Predictor()


class FlowFeatures(BaseModel):
    flow_duration: float = 0.0
    total_fwd_packets: int = 0
    total_bwd_packets: int = 0
    total_fwd_bytes: float = 0.0
    total_bwd_bytes: float = 0.0
    fwd_pkt_len_mean: float = 0.0
    bwd_pkt_len_mean: float = 0.0
    flow_bytes_per_s: float = 0.0
    flow_pkts_per_s: float = 0.0
    flow_iat_mean: float = 0.0
    syn_flag_count: int = 0
    rst_flag_count: int = 0


@app.get("/health")
def health():
    return {"status": "ok", "features": FEATURES}


@app.post("/predict")
def predict(flow: FlowFeatures):
    return predictor.predict(flow.model_dump())
