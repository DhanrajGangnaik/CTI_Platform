FROM python:3.11-slim

# Workdir
WORKDIR /app

# Install system deps (if you need any, e.g. libxml / libxslt, etc.)
RUN apt-get update && apt-get install -y \
    build-essential \
    && rm -rf /var/lib/apt/lists/*

# Copy files
COPY . /app

# Install Python deps
# (if your requirements.txt is in config/, adjust path)
RUN pip install --no-cache-dir -r config/requirements.txt

# Expose port used by uvicorn
EXPOSE 8000

# Run the app
CMD ["uvicorn", "app:app", "--host", "0.0.0.0", "--port", "8000"]
