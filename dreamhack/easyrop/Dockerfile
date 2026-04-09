FROM ubuntu@sha256:728785b59223d755e3e5c5af178fab1be7031f3522c5ccd7a0b32b80d8248123

RUN apt-get update && \
    apt-get upgrade -y && \
    apt-get install -y socat && \
    rm -rf /var/lib/apt/lists/*

ENV TERM=linux

RUN groupadd pwn && useradd -g pwn pwn

WORKDIR /home/pwn

COPY prob /home/pwn/prob
COPY flag /home/pwn/flag

RUN chmod 460 /home/pwn/flag && \
    chmod +x /home/pwn/prob && \
    chown pwn:root /home/pwn/prob /home/pwn/flag && \
    chmod o-rx /home/pwn/prob /home/pwn/flag

USER pwn

EXPOSE 1337
CMD socat TCP-LISTEN:1337,reuseaddr,fork EXEC:"./prob",stderr
