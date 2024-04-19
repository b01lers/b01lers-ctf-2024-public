FROM node:alpine

WORKDIR /app
COPY src/app.js /app
RUN mkdir static
COPY src/static/ /app/static

RUN yarn add express

CMD ["node", "app.js"]
