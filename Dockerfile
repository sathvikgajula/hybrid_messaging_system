# Use lightweight Python
FROM python:3.9-slim

# Set working directory
WORKDIR /app

# Install dependencies (Crypto + Testing tools)
RUN pip install --no-cache-dir pycryptodome hypothesis pytest

# Copy source code
COPY . .

# Default command: Run the CLI
CMD ["python", "main.py"]