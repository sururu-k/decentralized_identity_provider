# syntax=docker/dockerfile:1
#
# The build context is the REPOSITORY ROOT, not projects/gateway/, because the image also
# carries the built demo UI from projects/demo/ (docs/container-split.md section 6):
#
#   docker build -f projects/gateway/Dockerfile -t pasta-gateway .
#
# The root .dockerignore keeps the context small; projects/demo/src and projects/gateway/src
# are the only sources that travel.

# --- stage 1: build the React demo UI ---------------------------------------
FROM node:22-alpine AS ui
WORKDIR /ui
COPY projects/demo/package.json projects/demo/package-lock.json ./
RUN npm ci
COPY projects/demo/ ./
RUN npm run build

# --- stage 2: compile the gateway -------------------------------------------
FROM node:22-alpine AS build
WORKDIR /app
COPY projects/gateway/package.json projects/gateway/package-lock.json ./
RUN npm ci
COPY projects/gateway/tsconfig.json ./
COPY projects/gateway/src ./src
RUN npm run build

# --- stage 3: production dependencies only -----------------------------------
FROM node:22-alpine AS deps
WORKDIR /app
COPY projects/gateway/package.json projects/gateway/package-lock.json ./
RUN npm ci --omit=dev

# --- runtime -----------------------------------------------------------------
FROM node:22-alpine AS runtime
WORKDIR /app
ENV NODE_ENV=production
ENV PORT=3000
ENV GROUP_CONFIG=/secrets/group.json
ENV DEMO_DIST=/app/ui
# Demo logging (docs/container-split.md section 10). `docker compose logs` is not a TTY,
# so colour has to be forced on here; `DEMO_LOG=0` or `FORCE_COLOR=0` turns each off.
ENV DEMO_LOG=1
ENV FORCE_COLOR=1

COPY --from=deps /app/node_modules ./node_modules
COPY --from=build /app/dist ./dist
COPY --from=ui /ui/dist ./ui
COPY projects/gateway/package.json ./

# Unprivileged user shipped with the base image (uid 1000). The gateway only reads
# group.json, so mount the secrets directory read-only.
USER node

EXPOSE 3000

# alpine has no curl, so the check runs through the Node runtime that is already here.
# Standard values from docs/container-split.md section 8. The gateway opens its port only
# after node discovery has resolved every NODE_URLS entry, so the first few probes fail
# with a refused connection rather than a bad answer; with a 5s interval and 3 retries
# that leaves room for a slow start without stretching start-period.
HEALTHCHECK --interval=5s --timeout=3s --start-period=3s --retries=3 \
  CMD node -e "fetch('http://127.0.0.1:' + (process.env.PORT || 3000) + '/health').then(r => process.exit(r.ok ? 0 : 1)).catch(() => process.exit(1))"

CMD ["node", "/app/dist/index.js"]
