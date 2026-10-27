FROM python:3.11-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

RUN groupadd -r red && useradd -r -g red -d /app -s /sbin/nologin red

WORKDIR /app

RUN mkdir -p /data/red_payloads && chown -R red:red /data/red_payloads

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

USER red

EXPOSE 8000
CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8000", "--no-access-log"]
