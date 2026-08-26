# Dockerfile for FastAPI + ML Backend Service
FROM python:3.11-slim

WORKDIR /app

# Install system dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    libpq-dev \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Copy requirements and install Python packages
COPY backend/requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy backend code, ML models, and threat intel catalogs
COPY backend/ /app/backend/
COPY ml/ /app/ml/
COPY simulation/ /app/simulation/
COPY threat_intelligence/ /app/threat_intelligence/

ENV PYTHONPATH="/app/backend:/app"
ENV PYTHONUNBUFFERED=1

EXPOSE 8000

CMD ["uvicorn", "backend.app.main:app", "--host", "0.0.0.0", "--port", "8000"]
