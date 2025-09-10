FROM node:23.9.0-alpine
WORKDIR /app
COPY package.json package-lock.json ./
RUN npm ci --production

COPY .env .env
COPY . .
EXPOSE 3000
CMD ["node", "server.js"]
