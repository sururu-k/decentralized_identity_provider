# ---- build stage: compile TypeScript to dist/ ----
FROM node:22-alpine AS build
WORKDIR /app
COPY package.json package-lock.json ./
RUN npm ci
COPY tsconfig.json ./
COPY src ./src
RUN npm run build

# ---- deps stage: production dependencies only ----
FROM node:22-alpine AS deps
WORKDIR /app
COPY package.json package-lock.json ./
RUN npm ci --omit=dev

# ---- runtime stage ----
FROM node:22-alpine
WORKDIR /app
ENV NODE_ENV=production
ENV NODE_CONFIG=/secrets/node.json
ENV PORT=4000
# The demo trace of docs/container-split.md section 10. `docker compose logs` is not a
# TTY, so colour would be dropped there and the columns of the demo would be hard to tell
# apart; the image asks for it explicitly. `NO_COLOR=1` or `FORCE_COLOR=0` turns it back
# off, `DEMO_LOG=0` removes the trace entirely.
ENV DEMO_LOG=1
ENV FORCE_COLOR=1

COPY --from=deps /app/node_modules ./node_modules
COPY --from=build /app/dist ./dist
COPY package.json ./

# Unprivileged user shipped with the base image (uid 1000). The node only ever reads
# its config, so mount the secrets directory read-only.
USER node

EXPOSE 4000

# alpine has no curl, so the check runs through the Node runtime that is already here.
# The interval is short on purpose: compose gates the gateway on `service_healthy`, and
# the engine here (< 25.0) has no `--start-interval`, so the very first probe only runs
# one full interval after the container starts. A node is listening well under a second,
# so a 10s interval would have held the whole stack back by 10s for nothing.
HEALTHCHECK --interval=5s --timeout=3s --start-period=3s --retries=3 \
  CMD node -e "fetch('http://127.0.0.1:' + (process.env.PORT || 4000) + '/health').then(r => process.exit(r.ok ? 0 : 1)).catch(() => process.exit(1))"

CMD ["node", "/app/dist/index.js"]
