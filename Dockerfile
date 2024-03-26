# Use an official Python runtime as a parent image
FROM python:3.9-slim

ENV PYTHONDONTWRITEBYTECODE 1
ENV PYTHONUNBUFFERED 1
ENV FLASK_APP=app.py
ENV FLASK_RUN_HOST=0.0.0.0

WORKDIR /app

RUN apt-get update \
    && apt-get install -y netcat-openbsd gcc \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt /app/
RUN pip install --no-cache-dir -r requirements.txt

RUN pip install gunicorn

COPY . /app/

EXPOSE 5000

# Command to run the Flask application using Flask's development server for debugging
#CMD ["flask", "run"]
CMD ["gunicorn", "app:app", "--bind", "0.0.0.0:5000"]
#CMD ["flask", "run", "--host=0.0.0.0"]