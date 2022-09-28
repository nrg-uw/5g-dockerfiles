FROM python:3.8-slim
LABEL maintainer="Niloy Saha <niloysaha.ns@gmail.com>"
LABEL description="Free5GC UPF Exporter v2.0.0"

RUN pip install prometheus_client
RUN mkdir -p /exporter/

WORKDIR /exporter

COPY /app/* ./

EXPOSE 9000