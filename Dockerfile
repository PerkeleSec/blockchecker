FROM python:3.9-slim
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY blocklist.py .
COPY sample_ips.txt /app/data/sample_ips.txt
VOLUME /app/input
CMD ["python", "-u", "blocklist.py"]
