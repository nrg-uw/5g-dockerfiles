FROM ghcr.io/niloysh/free5gc-base:v3.2.0 AS builder
FROM ubuntu:20.04
ENV F5GC_MODULE amf
LABEL maintainer="Niloy Saha <niloysaha.ns@gmail.com>"
LABEL description="Free5GC AMF v3.2.0"
ENV DEBIAN_FRONTEND=noninteractive
ARG DEBUG_TOOLS

# Install debug tools ~ 100MB (if DEBUG_TOOLS is set to true)
RUN if [ "$DEBUG_TOOLS" = "true" ] ; then apt-get update && apt-get install -y vim strace net-tools iputils-ping curl netcat ; fi


RUN mkdir -p /free5gc/config
WORKDIR /free5gc

# Copy executable and default configuration
COPY --from=builder /free5gc/${F5GC_MODULE} ./

# Copy linked libs
COPY --from=builder /free5gc/libgtp5gnl.so.0 /usr/local/lib
COPY --from=builder /free5gc/liblogger.so /usr/local/lib

COPY /app/* ./

# Update links
RUN ldconfig