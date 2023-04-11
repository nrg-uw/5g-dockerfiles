FROM ghcr.io/niloysh/free5gc-aio:v3.2.0 AS builder
FROM ubuntu:20.04
LABEL maintainer="Niloy Saha <niloysaha.ns@gmail.com>"
LABEL description="Free5GC UPF v3.2.0 with pdr stats"
ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update \
    && apt-get -y install git gcc cmake autoconf libtool pkg-config libmnl-dev libyaml-dev \
    && apt-get -y install vim net-tools curl \
    && apt-get install -y libmnl0 libyaml-0-2 iproute2 iptables python3 iperf3 tcpdump \
    && apt-get clean


WORKDIR /free5gc

RUN git clone -b v0.5.0 https://github.com/niloysh/libgtp5gnl.git
RUN cd /free5gc/libgtp5gnl \
    && autoreconf -iv \
    && ./configure --prefix=`pwd` \
    && make

# Copy executable and default certs
COPY --from=builder /free5gc/* ./
COPY --from=builder /free5gc/config/TLS/*.pem ./config/TLS/
COPY --from=builder /free5gc/config/TLS/*.key ./config/TLS/

COPY /app/* ./

EXPOSE 8000
