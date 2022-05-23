# Based on https://github.com/free5gc/free5gc-compose
FROM golang:1.14.4-stretch AS builder

# Install dependencies
RUN apt-get update \
    && apt-get -y install gcc cmake autoconf libtool pkg-config libmnl-dev libyaml-dev apt-transport-https ca-certificates

# Clean apt cache
RUN apt-get clean

# Get Free5GC
RUN cd $GOPATH/src \
    && git clone --recursive -b v3.0.5 -j `nproc` https://github.com/free5gc/free5gc.git

WORKDIR $GOPATH/src/free5gc

# update .submodules to point to custom SMF source
RUN sed -i 's#https://github.com/free5gc/smf.git#https://github.com/niloysh/smf.git#g' .gitmodules
RUN git submodule sync --recursive

# checkout and build SMF v3.0.5.1 which logs slice information
RUN cd NFs/smf && git fetch && git checkout v3.0.5.1
RUN make smf

FROM alpine:3.15
LABEL maintainer="Niloy Saha <niloysaha.ns@gmail.com>"
LABEL description="Free5GC SMF v3.0.5"
ARG DEBUG_TOOLS

# Install debug tools
RUN if [ "$DEBUG_TOOLS" = "true" ] ; then apk add -U vim net-tools curl; fi

WORKDIR /free5gc
RUN mkdir -p config/ log/

# Copy executables
COPY --from=builder /go/src/free5gc/bin/* ./

# Copy configuration files (not used for now)
COPY --from=builder /go/src/free5gc/config/* ./config/

# Config files volume
VOLUME [ "/free5gc/config" ]

# Exposed ports
EXPOSE 8000
