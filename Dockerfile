# ---- build ----
# 版を固定（2026-11-15 時点の node:22-alpine）。更新するときはダイジェストごと差し替える
FROM node:22-alpine@sha256:1314fb30ec37592d5845e5a160d522c0e680972aa534549940b8d73bde88481a AS build
WORKDIR /app
COPY package.json package-lock.json ./
COPY server/package.json ./server/
COPY web/package.json ./web/
RUN npm ci --no-audit --no-fund
COPY server ./server
COPY web ./web
RUN npm run build

# ---- runtime ----
FROM node:22-alpine@sha256:1314fb30ec37592d5845e5a160d522c0e680972aa534549940b8d73bde88481a
RUN apk add --no-cache openssl tini \
 && addgroup -S app && adduser -S app -G app \
 && mkdir -p /app/data && chown app:app /app/data
WORKDIR /app
COPY package.json package-lock.json ./
COPY server/package.json ./server/
COPY web/package.json ./web/
RUN npm ci --omit=dev --no-audit --no-fund --workspace=server && npm cache clean --force
COPY --from=build /app/server/dist ./server/dist
COPY --from=build /app/web/dist ./web/dist
COPY config ./config
# EDR-130: installer templates for the agent packs (host screen -> Agent pack)
COPY installer/agent-pack ./installer/agent-pack
USER app
EXPOSE 8444
ENV NODE_ENV=production APP_DATA_DIR=/app/data
ENTRYPOINT ["/sbin/tini","--"]
CMD ["node","server/dist/index.js"]
