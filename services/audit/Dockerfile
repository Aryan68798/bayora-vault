FROM python:3.11-slim

# Non-root user ────────────────────────────────────────────────────────────────
RUN groupadd -r audit && useradd -r -g audit -d /app -s /sbin/nologin audit

# No .pyc files (read-only FS at runtime won't allow writing them anyway)
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

WORKDIR /app

# Install deps as root, then switch user
COPY requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

# Drop privileges
USER audit

EXPOSE 8000

# --no-access-log: access logs go to stdout but we don't want them polluting
# the audit stream; structured app events are logged instead.
CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8000", "--no-access-log"]
