FROM ubuntu:22.04

ENV DEBIAN_FRONTEND=noninteractive
ENV GO111MODULE=on
ENV PATH="/usr/local/go/bin:/root/go/bin:${PATH}"

RUN apt-get update -qq && apt-get install -y -qq \
    curl wget unzip git build-essential python3 python3-pip \
    tor xvfb x11vnc ffmpeg libssl-dev \
    && rm -rf /var/lib/apt/lists/*

# Go 1.22
RUN wget -q https://go.dev/dl/go1.22.4.linux-amd64.tar.gz -O /tmp/go.tar.gz \
    && tar -C /usr/local -xzf /tmp/go.tar.gz \
    && rm /tmp/go.tar.gz

# Install script
COPY install.sh /tmp/install.sh
RUN chmod +x /tmp/install.sh && bash /tmp/install.sh

WORKDIR /rhodawk

VOLUME ["/rhodawk"]

CMD ["python3", "/rhodawk/rhodawk.py"]
