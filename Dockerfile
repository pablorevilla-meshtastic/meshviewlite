FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

WORKDIR /app

COPY requirements.txt /app/requirements.txt
RUN pip install --no-cache-dir -r /app/requirements.txt

COPY meshviewlite.py /app/meshviewlite.py
COPY meshviewlite_web.py /app/meshviewlite_web.py
COPY portmaps.js /app/portmaps.js
COPY templates /app/templates
COPY docker/entrypoint.sh /entrypoint.sh

RUN chmod +x /entrypoint.sh

VOLUME ["/data"]
EXPOSE 8050

ENTRYPOINT ["/entrypoint.sh"]
CMD ["collector"]
