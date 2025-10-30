FROM python:3.11-slim

ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1

WORKDIR /app

COPY requirements.txt /app/
RUN pip install --no-cache-dir -r requirements.txt

COPY . /app

EXPOSE 5000

# Run using gunicorn (bind to 0.0.0.0:5000)
CMD ["gunicorn", "-b", "0.0.0.0:5000", "app:app", "--workers=2", "--threads=2"]
