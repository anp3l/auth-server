FROM node:20-alpine

WORKDIR /app

COPY package*.json ./

RUN npm ci

COPY . .

RUN chown -R node:node /app

USER node

EXPOSE 4000


CMD ["npm", "start"]
