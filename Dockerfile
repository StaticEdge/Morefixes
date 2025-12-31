FROM python:3.10-slim

ENV PYTHONUNBUFFERED=1
WORKDIR /app

# System deps needed for building some Python packages and for postgres client
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential gcc git wget unzip libpq-dev curl \
 && rm -rf /var/lib/apt/lists/*

COPY requirements.txt /app/
RUN pip install --upgrade pip setuptools wheel \
 && pip install -r requirements.txt

COPY . /app
ENV PYTHONPATH=/app

RUN chmod +x /app/Code/run.sh

CMD ["bash", "/app/Code/run.sh"]
