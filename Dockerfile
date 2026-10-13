FROM python:3.12-slim
ENV PYTHONUNBUFFERED=1 LOGSENSE_HOSTED=1 LOGSENSE_DATA=/data
WORKDIR /app
COPY requirements.txt requirements-cloud.txt ./
RUN pip install --no-cache-dir -r requirements.txt -r requirements-cloud.txt
COPY . .
RUN useradd -m app && mkdir -p /data && chown -R app /data /app
USER app
VOLUME /data
EXPOSE 8000
HEALTHCHECK --interval=30s --timeout=5s CMD python -c "import os,urllib.request;urllib.request.urlopen('http://localhost:%s/healthz'%os.getenv('PORT','8000'))" || exit 1
# ONE worker on purpose: it also runs the live poller thread
CMD ["sh", "-c", "uvicorn logsense.app:app --host 0.0.0.0 --port ${PORT:-8000} --proxy-headers --forwarded-allow-ips='*' --workers 1"]
