FROM python:3.11-slim

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

RUN mkdir -p /app/data
VOLUME ["/app/data"]

ENV PLAGUARDSV2_DB=/app/data/plaguardsv2.db
EXPOSE 8000

CMD ["gunicorn", "-b", "0.0.0.0:8000", "-w", "2", "--timeout", "60", "wsgi:app"]
