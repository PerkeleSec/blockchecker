FROM python:3.9-slim

# Set working directory
WORKDIR /app

# Copy requirements and install dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application files
COPY blocklist.py .
COPY sample_ips.txt /app/data/sample_ips.txt

# Create a volume mount point for user input files
VOLUME /app/input

CMD ["python", "-u", "blocklist.py"]
