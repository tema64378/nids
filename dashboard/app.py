"""Живой дашборд NIDS (Streamlit).

  streamlit run dashboard/app.py

Читает алерты из data/alerts.jsonl. Запусти `python -m tools.simulate` в другом
терминале, чтобы стримить алерты и смотреть, как дашборд наполняется в реальном времени.
"""

import os
import json
import time

import pandas as pd
import plotly.express as px
import streamlit as st

ALERTS_FILE = os.getenv("ALERTS_FILE", "data/alerts.jsonl")

# Единые цвета для каждого типа атаки во всех графиках.
COLORS = {
    "ATTACK": "#ef4444",
    "PortScan": "#f59e0b",
    "DoS": "#ef4444",
    "DDoS": "#dc2626",
    "BruteForce": "#a855f7",
    "WebAttack": "#ec4899",
    "Bot": "#14b8a6",
    "Infiltration": "#8b5cf6",
    "Heartbleed": "#f43f5e",
}

st.set_page_config(page_title="NIDS Дашборд", page_icon="🛡️", layout="wide")

# ---- немного стилей, чтобы не выглядело как дефолтное Streamlit-приложение ----
st.markdown(
    """
    <style>
      div[data-testid="stMetric"] {
        background: #11161d;
        border: 1px solid #232b36;
        border-radius: 14px;
        padding: 16px 18px;
        box-shadow: 0 1px 3px rgba(0,0,0,.4);
      }
      div[data-testid="stMetricLabel"] { opacity: .7; }
      .banner {
        border-radius: 14px; padding: 18px 22px; margin: 6px 0 18px 0;
        font-size: 1.15rem; font-weight: 600;
      }
      .banner.calm  { background: #0f2a1a; border: 1px solid #1f6f43; color: #4ade80; }
      .banner.alarm { background: #2a0f12; border: 1px solid #7f1d1d; color: #f87171; }
      .block-title { font-size: 1.05rem; font-weight: 700; margin: 8px 0 2px 0; }
      .hint { opacity: .6; font-size: .85rem; margin-bottom: 8px; }
    </style>
    """,
    unsafe_allow_html=True,
)

# ---------------- панель управления (сайдбар) ----------------
st.sidebar.title("⚙️ Управление")
live = st.sidebar.toggle("🔴 Живой режим", value=True, help="Автообновление страницы")
refresh = st.sidebar.slider("Обновлять каждые (сек)", 1, 10, 2)
min_conf = st.sidebar.slider("Мин. уверенность", 0.0, 1.0, 0.0, 0.05,
                             help="Скрывать алерты с уверенностью модели ниже этого порога")
window_min = st.sidebar.selectbox("Окно времени", [5, 15, 60, 24 * 60], index=2,
                                  format_func=lambda m: f"последние {m} мин" if m < 60 else f"последние {m // 60} ч")
st.sidebar.caption("Запустить демо-поток алертов:\n`python -m tools.simulate`")


def load_alerts():
    if not os.path.exists(ALERTS_FILE):
        return pd.DataFrame()
    rows = []
    with open(ALERTS_FILE) as f:
        for line in f:
            line = line.strip()
            if line:
                try:
                    rows.append(json.loads(line))
                except json.JSONDecodeError:
                    continue
    return pd.DataFrame(rows)


st.title("🛡️ NIDS — Обнаружение сетевых вторжений")

df = load_alerts()
if not df.empty:
    df["time"] = pd.to_datetime(df["ts"], unit="s")
    df = df[df["confidence"] >= min_conf]
    cutoff = pd.Timestamp.utcnow().tz_localize(None) - pd.Timedelta(minutes=window_min)
    df = df[df["time"] >= cutoff]

# ---------------- статус-баннер ----------------
recent = df[df["ts"] >= time.time() - 30] if not df.empty else pd.DataFrame()
if not recent.empty:
    top = recent["label"].value_counts().idxmax()
    st.markdown(
        f'<div class="banner alarm">🚨 Активная угроза — {len(recent)} алерт(ов) за '
        f'последние 30 с · преобладает: <b>{top}</b></div>',
        unsafe_allow_html=True,
    )
else:
    st.markdown(
        '<div class="banner calm">✅ Угроз нет — трафик выглядит чистым</div>',
        unsafe_allow_html=True,
    )

# ---------------- KPI-карточки ----------------
c1, c2, c3, c4 = st.columns(4)
c1.metric("Алертов (за окно)", len(df), help="Атак обнаружено за выбранное окно времени")
c2.metric("Уникальных атакующих", int(df["src"].nunique()) if not df.empty else 0,
          help="Различных source IP, помеченных как атака")
c3.metric("Топ-тип атаки", df["label"].value_counts().idxmax() if not df.empty else "—",
          help="Самая частая категория атаки")
c4.metric("Средняя уверенность", f"{df['confidence'].mean():.2f}" if not df.empty else "—",
          help="Средняя уверенность модели по всем алертам")

st.divider()

if df.empty:
    st.info("За это окно времени алертов пока нет. Запусти симулятор "
            "(`python -m tools.simulate`) или живой сниффер, чтобы наполнить дашборд.")
else:
    # ---------------- таймлайн ----------------
    st.markdown('<div class="block-title">📈 Атаки во времени</div>', unsafe_allow_html=True)
    st.markdown('<div class="hint">Каждая точка — обнаруженная атака. Y = уверенность модели, '
                'цвет = тип атаки, размер = число пакетов.</div>', unsafe_allow_html=True)
    fig = px.scatter(
        df, x="time", y="confidence", color="label", size="packets",
        color_discrete_map=COLORS, hover_data=["src", "dst", "packets"],
        template="plotly_dark",
        labels={"time": "Время", "confidence": "Уверенность", "label": "Тип атаки"},
    )
    fig.update_layout(height=340, margin=dict(l=10, r=10, t=10, b=10),
                      legend_title_text="Тип атаки")
    st.plotly_chart(fig, use_container_width=True)

    left, right = st.columns(2)
    with left:
        st.markdown('<div class="block-title">🎯 Типы атак</div>', unsafe_allow_html=True)
        counts = df["label"].value_counts().reset_index()
        counts.columns = ["label", "count"]
        donut = px.pie(counts, names="label", values="count", hole=0.55,
                       color="label", color_discrete_map=COLORS, template="plotly_dark")
        donut.update_layout(height=300, margin=dict(l=10, r=10, t=10, b=10))
        st.plotly_chart(donut, use_container_width=True)

    with right:
        st.markdown('<div class="block-title">🌐 Топ source IP</div>', unsafe_allow_html=True)
        top_src = df["src"].value_counts().head(8).reset_index()
        top_src.columns = ["src", "alerts"]
        bar = px.bar(top_src, x="alerts", y="src", orientation="h",
                     template="plotly_dark", color_discrete_sequence=["#ef4444"],
                     labels={"alerts": "Алертов", "src": "IP-адрес"})
        bar.update_layout(height=300, margin=dict(l=10, r=10, t=10, b=10),
                          yaxis={"categoryorder": "total ascending"})
        st.plotly_chart(bar, use_container_width=True)

    # ---------------- таблица последних алертов ----------------
    st.markdown('<div class="block-title">📋 Последние алерты</div>', unsafe_allow_html=True)
    table = df.sort_values("ts", ascending=False).head(50).copy()
    table["time"] = table["time"].dt.strftime("%H:%M:%S")
    table = table[["time", "label", "src", "dst", "packets", "confidence"]]
    st.dataframe(
        table, use_container_width=True, hide_index=True,
        column_config={
            "time": "Время",
            "label": "Тип",
            "src": "Source IP",
            "dst": "Dest IP",
            "packets": "Пакетов",
            "confidence": st.column_config.ProgressColumn(
                "Уверенность", min_value=0.0, max_value=1.0, format="%.2f"),
        },
    )

if live:
    time.sleep(refresh)
    st.rerun()
