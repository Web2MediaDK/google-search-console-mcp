FROM python:3.12-slim
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY spike_server.py .
# Cloud Run sets PORT (8080 by default); the server reads it.
CMD ["python", "spike_server.py"]
