# Cımbız - Güvenlik Açığı Tarayıcı Dockerfile
FROM python:3.11-slim

WORKDIR /app

COPY . /app

RUN pip install --no-cache-dir -r requirements.txt

EXPOSE 8501
EXPOSE 5000

CMD ["streamlit", "run", "gui.py"]
