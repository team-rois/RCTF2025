FROM node:20-slim as builder
WORKDIR /build

COPY package.json postcss.config.js tailwind.config.js ./
COPY static/css/tailwind-input.css ./static/css/tailwind-input.css

RUN npm install
RUN npm run build:css

FROM python:3.11-slim

ENV PYTHONUNBUFFERED=1
ENV PYTHONDONTWRITEBYTECODE=1

WORKDIR /app

COPY --from=builder /build/static/css/style.css /app/static/css/style.css

COPY requirements.txt .

RUN pip install --no-cache-dir -r requirements.txt gunicorn

COPY . .

EXPOSE 80

CMD ["gunicorn", "--workers", "4", "--bind", "0.0.0.0:80", "wsgi:app"]