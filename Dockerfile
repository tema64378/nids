FROM python:3.12-slim

WORKDIR /app

# libpcap нужен scapy для живого захвата.
RUN apt-get update \
    && apt-get install -y --no-install-recommends libpcap0.8 \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

# Сервис по умолчанию: API. docker-compose переопределяет команду для каждого сервиса.
CMD ["uvicorn", "api.main:app", "--host", "0.0.0.0", "--port", "8000"]
