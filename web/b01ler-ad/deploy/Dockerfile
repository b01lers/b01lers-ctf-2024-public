FROM node:21-alpine

ENV LANG="C.UTF-8" PUPPETEER_SKIP_CHROMIUM_DOWNLOAD=true

RUN apk update
RUN apk add --no-cache zlib-dev udev nss ca-certificates
RUN apk add --no-cache chromium
RUN adduser -h /home/bot -D -u 10086 bot
RUN yarn cache clean
RUN rm -rf /tmp/* /etc/apk/* /var/cache/apk/* /usr/share/man

# Setting up the work directory
WORKDIR /b01lersapp-docker

# Copying all the files in our project
COPY ./src /b01lersapp-docker

# Installing dependencies
RUN npm install

# Starting our application
CMD [ "node", "index.js" ]

# Exposing server port
EXPOSE 3000