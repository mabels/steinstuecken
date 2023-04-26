FROM alpine:3

RUN apk add --no-cache ca-certificates tzdata iptables ip6tables ipset iproute2

COPY ./steinstuecken /bin/steinstuecken

ENTRYPOINT ["steinstuecken"]

