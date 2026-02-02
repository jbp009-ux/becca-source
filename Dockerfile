FROM python:3.11-slim

WORKDIR /app

# Copy requirements and install dependencies
COPY requirements-deploy.txt .
RUN pip install --no-cache-dir -r requirements-deploy.txt

# Copy application files
COPY becca_chat.py .
COPY templates/ ./templates/
COPY governance/ ./governance/
COPY prompts/ ./prompts/

# Expose port
EXPOSE 8080

# Run with gunicorn
CMD ["gunicorn", "--bind", "0.0.0.0:8080", "--timeout", "300", "--workers", "2", "becca_chat:app"]
