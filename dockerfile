FROM ubuntu:latest

RUN apt-get update && apt-get install -y \
    build-essential \
    inetutils-ping \
    valgrind \
    git \
    vim \
    fish


WORKDIR /root/src

CMD ["fish"]