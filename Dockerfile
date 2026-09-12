FROM python:3.12-slim

WORKDIR /app

RUN useradd --system --uid 1000 --create-home sealed

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt \
    && pip install --no-cache-dir uvicorn[standard]

COPY aes_utils.py database.py elgamal_utils.py keyfile.py main.py \
     netconfig.py protocol.py rabin_utils.py rsa_utils.py server.py ./

USER sealed
ENV SEALED_BIND=0.0.0.0
ENV SEALED_PORT=8000
ENV PYTHONUNBUFFERED=1

EXPOSE 8000
CMD ["python", "main.py", "server"]
