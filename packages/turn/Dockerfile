FROM alpine:3.20

RUN apk add --no-cache coturn curl && rm -rf /var/cache/apk/*

COPY config/turnserver.conf /etc/coturn/turnserver.conf.tmpl
COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

# 3478 TCP/UDP — plain TURN
# 5349 TCP     — TURNS (TURN over TLS, terminated by Fly.io)
# 49152-65535  — TURN relay port range
EXPOSE 3478/tcp 3478/udp 5349/tcp

ENTRYPOINT ["/entrypoint.sh"]
