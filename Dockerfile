# syntax=docker/dockerfile:1

FROM python:3.9.5 AS builder

COPY requirements.txt .
RUN pip install --user -r requirements.txt

FROM python:3.9.5-slim AS app

WORKDIR /app

COPY --from=builder /root/.local /root/.local
COPY sslscan.py .

ENV PATH=/root/.local:$PATH

ENTRYPOINT ["python", "./sslscan.py"]
