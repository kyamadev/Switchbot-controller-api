FROM python:3.12.9-bullseye

ENV PYTHONDONTWRITEBYTECODE 1
ENV PYTHONUNBUFFERED 1

WORKDIR /app

RUN apt-get update \
    && apt-get install -y --no-install-recommends netcat \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.lock /app/
RUN pip install --no-cache-dir -r requirements.lock

COPY . /app/

RUN chmod +x /app/entrypoint.sh

RUN python manage.py collectstatic --noinput

EXPOSE 8000

ENTRYPOINT ["/app/entrypoint.sh"]