# /auto-selector/Dockerfile
FROM node:20-alpine
WORKDIR /app
COPY package.json package-lock.json* ./ 
RUN npm ci --omit=dev || npm i --omit=dev
COPY server.js ./
ENV PORT=8090 HOST=0.0.0.0
CMD ["node", "server.js"]
