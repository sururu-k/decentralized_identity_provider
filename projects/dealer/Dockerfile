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
COPY --from=deps /app/node_modules ./node_modules
COPY --from=build /app/dist ./dist
COPY package.json ./

# The dealer is a one-shot CLI, not a server, so it defines no HEALTHCHECK.
# It runs as the unprivileged `node` user (uid 1000); the mounted output
# directory must be writable by that uid, or pass `--user "$(id -u):$(id -g)"`.
USER node

ENTRYPOINT ["node", "/app/dist/index.js"]
CMD ["--help"]
