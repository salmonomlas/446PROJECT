FROM nginx:1.28.0-alpine

# Install the headers_more module
RUN apk add --no-cache nginx-mod-http-headers-more

# Copy in your custom config and certs
COPY nginx.conf /etc/nginx/nginx.conf
COPY certs /etc/nginx/certs