FROM node:20.12.0-bookworm-slim AS build
WORKDIR /app
RUN apt-get update && apt-get install -y \
	g++ make cmake unzip libcurl4-openssl-dev autoconf libtool python3 curl
COPY package.json ./
COPY package-lock.json ./
RUN npm ci

FROM node:20.12.0-bookworm-slim
WORKDIR /app
RUN apt-get update && apt-get install -y --no-install-recommends \
	unzip libglib2.0-0 libnss3 libatk1.0-0 libatk-bridge2.0-0 libcups2 libdrm2 \
	libxkbcommon0 libxcomposite1 libxdamage1 libxrandr2 libgbm1 libgtk-3-0 \
	libasound2 libxshmfence1 libx11-xcb1 libcap2-bin && rm -rf /var/lib/apt/lists/*
COPY --link --from=build app/node_modules node_modules
COPY --link --from=build root/.cache/puppeteer /home/node/.cache/puppeteer
COPY --link src .
COPY ghostery ./ghostery

RUN setcap CAP_NET_BIND_SERVICE=+eip /usr/local/bin/node
USER node

ENV PORT=80
EXPOSE 80

CMD ["PORT=80 node --unhandled-rejections=strict submit.js & PORT=8081 node --unhandled-rejections=strict visit.js"]
ENTRYPOINT [ "/bin/bash" ,"-c"]

VOLUME /tmp /run