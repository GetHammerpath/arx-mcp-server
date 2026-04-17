FROM python:3.11-slim

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY main.py .

ENV ARXSEC_API_URL=http://arxsec-api:8000
ENV LOG_LEVEL=INFO

CMD ["python", "main.py"]
