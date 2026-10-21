FROM python:3.12-slim-bookworm
WORKDIR /app
COPY requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt
COPY app.py ./
RUN useradd -u 10001 inventory
USER 10001
EXPOSE 8000
# Bound to the pod's loopback: the only way in is through the agentscd sidecar (and its charter).
CMD ["uvicorn", "app:app", "--host", "127.0.0.1", "--port", "8000"]
