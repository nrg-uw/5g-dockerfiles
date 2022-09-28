#!/usr/bin/env python3.8
# -*- coding: utf-8 -*-
#----------------------------------------------------------------------------
# Author: Niloy Saha
# Email: niloysaha.ns@gmail.com
# version ='2.0.0'
# ---------------------------------------------------------------------------
"""
Prometheus exporter which exports UPF PDR statistics from Free5gc UPF.
Expects to read a JSON log containing UPF statistics
"""
import prometheus_client as prom
import subprocess as subproc
import time
import json
import logging

# setup logger for console output
console_logger = logging.getLogger(__name__)
console_logger.setLevel(logging.INFO)
console_handler = logging.StreamHandler()
console_handler.setFormatter(logging.Formatter('%(asctime)s [%(levelname)s] [%(filename)s] %(message)s'))
console_logger.addHandler(console_handler)

UPF_STATS_FILE = "/var/log/upf_stats.log"
EXPORTER_PORT = 9000
UPDATE_PERIOD = 1  # seconds
CURRENT_STATS = None

STATS_FILE_CURRENT_FLAG = 0
STATS_FILE_PREV_FLAG = 0
STATS_FILE_INIT_FLAG = 0

# Prometheus variables
PDR_PACKET_COUNT = prom.Gauge('pdr_packet_count', 
                     'Cumulative packet counts per PDR', 
                     ['n3_ipaddr', 'n4_ipaddr','seid', 'pdrid', 'direction'])
PDR_BYTE_COUNT = prom.Gauge('pdr_byte_count', 
                     'Cumulative byte counts per PDR', 
                     ['n3_ipaddr', 'n4_ipaddr', 'seid', 'pdrid', 'direction'])

prom.REGISTRY.unregister(prom.PROCESS_COLLECTOR)
prom.REGISTRY.unregister(prom.PLATFORM_COLLECTOR)
prom.REGISTRY.unregister(prom.GC_COLLECTOR)

    
# get metrics for a particular timestamp
def get_metrics():

    try:

        completed_proc = subproc.run(["tail", "-n", "2", UPF_STATS_FILE], capture_output=True)
        stdout = completed_proc.stdout.decode("utf-8").strip()
        console_logger.debug(stdout)

        global STATS_FILE_CURRENT_FLAG, STATS_FILE_PREV_FLAG, STATS_FILE_INIT_FLAG

        if stdout:
            STATS_FILE_CURRENT_FLAG = 1
            if STATS_FILE_CURRENT_FLAG != STATS_FILE_PREV_FLAG:
                console_logger.info("UPF stats file found. Starting read")
                STATS_FILE_PREV_FLAG = STATS_FILE_CURRENT_FLAG

        if not stdout:
            STATS_FILE_CURRENT_FLAG = 0
            
            if not STATS_FILE_INIT_FLAG:
                console_logger.warning("No UPF stats file")
                STATS_FILE_INIT_FLAG = 1

            if STATS_FILE_CURRENT_FLAG != STATS_FILE_PREV_FLAG:
                console_logger.warning("No UPF stats file")
                STATS_FILE_PREV_FLAG = STATS_FILE_CURRENT_FLAG
            return

        data = json.loads(stdout)
        console_logger.debug(data)

        global CURRENT_STATS
        CURRENT_STATS = data

        for item in data:
            export_to_prometheus(item)
            
    
    except FileNotFoundError:
        console_logger.exception("Error in getting metrics!")

def export_to_prometheus(stats_item):

    pkt_count = stats_item["pkt_count"]
    byte_count = stats_item["byte_count"]
    pdrid = str(stats_item["pdrid"])
    seid = str(stats_item["seid"])
    n3_ipaddr = str(stats_item["upf_n3_ipaddr"])
    n4_ipaddr = str(stats_item["upf_n4_ipaddr"])


    PDR_PACKET_COUNT.labels(
        n3_ipaddr=n3_ipaddr, 
        n4_ipaddr=n4_ipaddr, 
        seid=seid, 
        pdrid=pdrid, 
        direction="uplink").set(pkt_count[0])
    PDR_PACKET_COUNT.labels(
        n3_ipaddr=n3_ipaddr, 
        n4_ipaddr=n4_ipaddr, 
        seid=seid, 
        pdrid=pdrid, 
        direction="downlink").set(pkt_count[1])

    PDR_BYTE_COUNT.labels(
        n3_ipaddr=n3_ipaddr, 
        n4_ipaddr=n4_ipaddr, 
        seid=seid, 
        pdrid=pdrid,
        direction="uplink").set(byte_count[0])
    PDR_BYTE_COUNT.labels(
        n3_ipaddr=n3_ipaddr, 
        n4_ipaddr=n4_ipaddr, 
        seid=seid, 
        pdrid=pdrid,
        direction="downlink").set(byte_count[1])




def main():
    console_logger.info("Starting Prometheus server on port {}".format(EXPORTER_PORT))
    prom.start_http_server(EXPORTER_PORT)

    while True:
        get_metrics()
        time.sleep(UPDATE_PERIOD)


if __name__ == "__main__":
    main()
