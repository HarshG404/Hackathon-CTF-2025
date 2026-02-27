# Use a slim version of Python 2026 stable
FROM python:3.11-slim

# Install system dependencies for the Ping tool (Command Injection challenge)
RUN apt-get update && apt-get install -y iputils-ping && rm -rf /var/lib/apt/lists/*

# Set working directory
WORKDIR /app

# Copy and install Python dependencies
# You'll need: Flask, PyJWT, Jinja2
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy the application code
COPY . .

# Create necessary directories (though app.py does this, it's safer here)
RUN mkdir -p uploads backup logs static/js

# Expose the Flask port
EXPOSE 5000

# Run the application
CMD ["python", "app.py"]