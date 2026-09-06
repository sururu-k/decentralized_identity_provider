# syntax=docker/dockerfile:1

# --- build stage -------------------------------------------------------------
FROM node:22-alpine AS builder
WORKDIR /app

# devDependencies (typescript) are needed only here.
COPY package.json package-lock.json ./
RUN npm ci

COPY tsconfig.json ./
COPY src ./src
RUN npm run build

# --- runtime stage -----------------------------------------------------------
FROM node:22-alpine AS runtime
WORKDIR /app
ENV NODE_ENV=production
ENV PORT=3001
# docker compose logs is not a TTY, so ANSI color would otherwise be off by
# default for the demo log (docs/container-split.md 第10節). Set FORCE_COLOR=0
# at `docker run`/compose time to fall back to plain text; DEMO_LOG=0 turns
# the demo log off entirely.
ENV DEMO_LOG=1
ENV FORCE_COLOR=1

# The RP has zero runtime dependencies (node:http + node:crypto only), so the
# runtime image carries compiled output and the package manifest, nothing else.
COPY package.json ./
COPY --from=builder /app/dist ./dist

USER node
EXPOSE 3001

# alpine has no curl; use the node runtime that is already present.
HEALTHCHECK --interval=5s --timeout=3s --start-period=3s --retries=3 \
  CMD node -e "fetch('http://127.0.0.1:' + (process.env.PORT || 3001) + '/health').then(r => process.exit(r.ok ? 0 : 1)).catch(() => process.exit(1))"

CMD ["node", "dist/index.js"]
