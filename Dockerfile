FROM node:22-alpine
WORKDIR /app
COPY package.json server.mjs lib.mjs alerts.mjs i18n.mjs report.mjs inventory.example.json ./
COPY public ./public
RUN mkdir -p data && chown node:node data
ENV HOST=0.0.0.0 PORT=4848
USER node
EXPOSE 4848
HEALTHCHECK --interval=60s --timeout=5s CMD wget -qO- http://127.0.0.1:4848/healthz || exit 1
CMD ["node", "server.mjs"]
