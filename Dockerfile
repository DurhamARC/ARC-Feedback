FROM python:3.13.2-slim-bookworm

# Set environment variables
ENV FLASK_APP=ORCiD_API_App.py
ENV FLASK_ENV=production

WORKDIR /app

# Install system dependencies
RUN apt-get update && \
    apt-get install -y --no-install-recommends postgresql-client && \
    rm -rf /var/lib/apt/lists/*

# Copy requirements first to leverage Docker cache
COPY requirements.txt .
RUN python -m pip install --upgrade pip
RUN pip install --no-cache-dir -r requirements.txt

# Copy application files
COPY conf/init-dev.sh /usr/local/bin/init.sh
RUN chmod +x /usr/local/bin/init.sh

COPY . .

WORKDIR /app/SearchApp

# Create necessary directories and set permissions
RUN mkdir -p instance && \
    chmod -R 755 instance/

EXPOSE 5000

ENTRYPOINT ["/usr/local/bin/init.sh"]
CMD ["flask", "run", "--host=0.0.0.0", "--port=5000"]
