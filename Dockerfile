FROM node:13-slim

WORKDIR /app

RUN npm install express mysql2

ADD . /app

CMD node index.js