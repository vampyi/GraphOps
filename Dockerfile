# build the dashboard, then serve it and the api from one python image.
# used by the `app` profile in docker-compose.yml: `docker compose --profile app up`.

FROM node:20-bookworm-slim AS web
WORKDIR /web
COPY frontend/package.json frontend/package-lock.json ./
RUN npm ci
COPY frontend/ ./
RUN npm run build

FROM python:3.12-slim
ENV PYTHONUNBUFFERED=1 PIP_NO_CACHE_DIR=1
WORKDIR /app
COPY backend/requirements.txt ./backend/requirements.txt
RUN pip install -r backend/requirements.txt
COPY backend/ ./backend/
COPY data/ ./data/
COPY --from=web /web/dist ./frontend/dist
COPY docker-entrypoint.sh /usr/local/bin/entrypoint.sh
RUN chmod +x /usr/local/bin/entrypoint.sh
WORKDIR /app/backend
EXPOSE 8000
CMD ["/usr/local/bin/entrypoint.sh"]
