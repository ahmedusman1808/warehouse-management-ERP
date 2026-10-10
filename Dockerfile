FROM node:22-alpine
WORKDIR /app
COPY package.json ./
RUN npm install --omit=dev
COPY index.html server.js ./
ENV NODE_ENV=production
EXPOSE 3000
USER node
CMD ["npm", "start"]
