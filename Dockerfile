# Dockerfile (replace your current file with this)
FROM python:3.9-slim

ENV PYTHONUNBUFFERED=1
ENV DEBIAN_FRONTEND=noninteractive


RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    gcc \
    libpq-dev \
    libssl-dev \
    libffi-dev \
    python3-dev \
    cargo \
    git \
  && rm -rf /var/lib/apt/lists/*

WORKDIR /app


COPY requirements.txt .

RUN python -m pip install --upgrade pip setuptools wheel
RUN pip install --no-cache-dir -r requirements.txt


COPY . .

EXPOSE 8000

# Adjust the CMD to match your app module if different
CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8000"]
