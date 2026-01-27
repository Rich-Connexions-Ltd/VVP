FROM python:3.12-slim
RUN apt-get update && apt-get install -y --no-install-recommends \
    libsodium23 libsodium-dev \
    ca-certificates \
  && rm -rf /var/lib/apt/lists/*
WORKDIR /srv
COPY pyproject.toml /srv/pyproject.toml
COPY app /srv/app
RUN pip install --no-cache-dir -U pip && pip install --no-cache-dir .
COPY web /srv/web
ENV PYTHONUNBUFFERED=1
EXPOSE 8000
CMD ["uvicorn", "app.main:app", "--host=0.0.0.0", "--port=8000"]
