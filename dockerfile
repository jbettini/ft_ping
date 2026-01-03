FROM ubuntu:latest

RUN apt-get update && apt-get install -y \
    build-essential \
    inetutils-ping \
    iptables \
    iproute2 \
    tcpdump \
    valgrind \
    gdb \
    git \
    vim \
    fish \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /root/src

CMD ["fish"]