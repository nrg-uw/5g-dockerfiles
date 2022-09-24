FROM niloysh/free5gc-base:v3.0.5 AS builder
FROM ubuntu:20.04
ENV F5GC_MODULE free5gc-upfd
LABEL maintainer="Niloy Saha <niloysaha.ns@gmail.com>"
LABEL description="Free5GC UPF v3.0.5"
ENV DEBIAN_FRONTEND=noninteractive
ARG DEBUG_TOOLS

# Install debug tools ~ 100MB (if DEBUG_TOOLS is set to true)
RUN if [ "$DEBUG_TOOLS" = "true" ] ; then apt-get update && apt-get install -y vim strace net-tools iputils-ping curl netcat ; fi

RUN apt-get update \
    && apt-get -y install git gcc cmake autoconf libtool pkg-config libmnl-dev libyaml-dev \
    libmnl0 libyaml-0-2 iproute2 iptables python3-pip \
    && apt-get clean

RUN pip install prometheus_client
RUN mkdir -p /free5gc/config

WORKDIR /free5gc

RUN git clone https://github.com/niloysh/libgtp5gnl.git
RUN cd /free5gc/libgtp5gnl \
    && autoreconf -iv \
    && ./configure --prefix=`pwd` \
    && make

# Copy executable and default configuration
COPY --from=builder /free5gc/${F5GC_MODULE} ./

# Copy linked libs
COPY --from=builder /free5gc/libgtp5gnl.so.0 /usr/local/lib
COPY --from=builder /free5gc/liblogger.so /usr/local/lib

COPY /app/* ./

# Update links
RUN ldconfig
