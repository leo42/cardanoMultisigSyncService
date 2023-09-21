from node:latest

WORKDIR /usr/src/app

COPY package*.json ./ 

RUN npm ci --only=production

RUN npm install typescript -g

COPY src/server.ts ./src/server.ts

RUN tsc src/server.ts

EXPOSE 3001

CMD ["node", "src/server.js"]
