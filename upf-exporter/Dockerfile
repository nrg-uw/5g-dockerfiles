FROM ubuntu:20.04

LABEL maintainer="Niloy Saha <niloysaha.ns@gmail.com>"
LABEL description="UPF stats exporter v3.0.0"
ENV DEBIAN_FRONTEND=noninteractive


RUN apt-get update \
    && apt-get -y install git gcc cmake autoconf libtool pkg-config libmnl-dev libyaml-dev \
    && apt-get -y install vim net-tools curl \
    && apt-get install -y libmnl0 libyaml-0-2 iproute2 iptables python3 python3-pip iperf3 tcpdump \
    && apt-get clean

WORKDIR /app

RUN git clone -b v0.5.0 https://github.com/niloysh/libgtp5gnl.git
RUN cd /app/libgtp5gnl \
    && autoreconf -iv \
    && ./configure --prefix=`pwd` \
    && make

RUN pip install prometheus_client


COPY /app/* ./

RUN chmod +x upf-exporter.py

EXPOSE 9000