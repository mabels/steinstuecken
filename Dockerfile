FROM scratch

COPY ./steinstuecken /bin/steinstuecken

ENTRYPOINT ["steinstuecken"]

