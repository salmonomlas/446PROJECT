FROM nginx:1.28.0-alpine

RUN apk add --no-cache nginx-mod-http-headers-more

COPY nginx.conf /etc/nginx/nginx.conf
COPY certs /etc/nginx/certs