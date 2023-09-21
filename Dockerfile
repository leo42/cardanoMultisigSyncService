from node:latest

WORKDIR /usr/src/app

COPY package.json ./ 

RUN npm ci --only=production

COPY src/server.ts ./src/server.ts

RUN tsc src/server.ts

EXPOSE 3000

CMD ["node", "src/server.js"]