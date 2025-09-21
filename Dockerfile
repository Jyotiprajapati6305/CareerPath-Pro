# Use an official Python slim image as base
FROM python:3.11-slim

# Install Tesseract OCR, Poppler, and dependencies
RUN apt-get update && apt-get install -y \
    tesseract-ocr \
    libtesseract-dev \
    libleptonica-dev \
    pkg-config \
    poppler-utils \
 && apt-get clean \
 && rm -rf /var/lib/apt/lists/*

# Set work directory
WORKDIR /app

# Copy requirements and install Python packages
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy all app files
COPY . .

# Expose port (Render will set PORT env, but we expose default here)
EXPOSE 5000

# Command to run gunicorn with 4 workers binding on Render's port
CMD ["sh", "-c", "gunicorn -w 4 -b 0.0.0.0:${PORT:-5000} app:app"]
