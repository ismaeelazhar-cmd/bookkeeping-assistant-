FROM python:3.12-slim

WORKDIR /app

COPY requirements-prod.txt requirements.txt ./
RUN pip install --no-cache-dir -r requirements-prod.txt

COPY server.py gunicorn.conf.py ./
COPY templates ./templates
COPY static ./static

# /data is where a mounted persistent volume should land — the database, uploaded
# attachments, and the session/encryption key files all live there (see DATA_DIR in
# server.py). Without a volume this still works, it just won't survive a redeploy.
ENV DATA_DIR=/data
ENV BIND_HOST=0.0.0.0
RUN mkdir -p /data

EXPOSE 5050
CMD ["gunicorn", "-c", "gunicorn.conf.py", "server:app"]
