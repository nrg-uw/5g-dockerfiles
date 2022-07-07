#!/usr/bin/env python3.8
# -*- coding: utf-8 -*-
#----------------------------------------------------------------------------
# Author: Niloy Saha
# Email: niloysaha.ns@gmail.com
# version ='1.0'
# ---------------------------------------------------------------------------
"""
Prometheus exporter which exports UPF PDR statistics from Free5gc UPF.
Expects to read a JSON file containing UPF statistics
"""
import prometheus_client as prom
import time
import json
import datetime
import logging
import threading

FORMAT = "%(filename)s: %(asctime)s %(levelname)s %(message)s"
logging.basicConfig(format=FORMAT, level=logging.INFO)

UPF_STATS_FILE = "/var/log/upf_stats.json"
EXPORTER_PORT = 9000
UPDATE_PERIOD = 5  # seconds
LOG_UPDATE_PERIOD = 30  # seconds
CURRENT_STATS = None

# Prometheus variables
PDR_PACKET_COUNT = prom.Gauge('pdr_packet_count', 
                     'Cumulative packet counts per PDR', 
                     ['pdr_id', 'direction'])
PDR_BYTE_COUNT = prom.Gauge('pdr_byte_count', 
                     'Cumulative byte counts per PDR', 
                     ['pdr_id', 'direction'])

prom.REGISTRY.unregister(prom.PROCESS_COLLECTOR)
prom.REGISTRY.unregister(prom.PLATFORM_COLLECTOR)
prom.REGISTRY.unregister(prom.GC_COLLECTOR)



def print_log_msg():
    threading.Timer(LOG_UPDATE_PERIOD, print_log_msg).start()
    if CURRENT_STATS:
        logging.info(CURRENT_STATS)
    else:
        logging.info("No current stats ...")

# get metrics for a particular timestamp
def get_metrics():

    try:
        with open(UPF_STATS_FILE, 'r') as f:
            # data should be list of dictionary items
            # where each item is stats belonging to a PDR
            data = json.load(f)

            global CURRENT_STATS
            CURRENT_STATS = data

            for item in data:
                export_to_prometheus(item)
    
    except FileNotFoundError:
        logging.info("UPF stats file not found. Sleeping 30s ...")
        time.sleep(30)

# takes a stats item in the following format and exports it to Prometheus format
# data = {
#         "timestamp" : str(timestamp),
#         "pdr_id": str(pdr_id),
#         "pkt_count" : [ul_pkt_cnt, dl_pkt_cnt],
#         "byte_count": [ul_byte_cnt, dl_byte_cnt]
#     }
def export_to_prometheus(stats_item):

    pkt_count = stats_item["pkt_count"]
    byte_count = stats_item["byte_count"]
    pdr_id = stats_item["pdr_id"]


    PDR_PACKET_COUNT.labels(pdr_id=str(pdr_id), direction="uplink").set(pkt_count[0])
    PDR_PACKET_COUNT.labels(pdr_id=str(pdr_id), direction="downlink").set(pkt_count[1])

    PDR_BYTE_COUNT.labels(pdr_id=str(pdr_id), direction="uplink").set(byte_count[0])
    PDR_BYTE_COUNT.labels(pdr_id=str(pdr_id), direction="downlink").set(byte_count[1])




def main():
    logging.info("Starting Prometheus server on port {}".format(EXPORTER_PORT))
    prom.start_http_server(EXPORTER_PORT)
    print_log_msg()
    while True:
        get_metrics()
        # period between collection
        time.sleep(UPDATE_PERIOD)


if __name__ == "__main__":
    main()

