# syntax=docker/dockerfile:1
FROM node:20-alpine

WORKDIR /app

# Install dependencies
COPY package.json package-lock.json* ./
RUN npm ci --omit=dev || npm i --omit=dev

# Copy source
COPY . .

# Ensure data dir exists for balances/topups/logs
RUN mkdir -p /app/data

ENV NODE_ENV=production

CMD ["node", "index.js"]


