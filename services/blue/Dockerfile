FROM python:3.11-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

RUN groupadd -r blue && useradd -r -g blue -d /app -s /sbin/nologin blue

WORKDIR /app

RUN mkdir -p /data/blue_rules && chown -R blue:blue /data/blue_rules

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

USER blue

EXPOSE 8000
CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8000", "--no-access-log"]
