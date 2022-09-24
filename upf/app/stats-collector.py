#!/usr/bin/env python3.8
# -*- coding: utf-8 -*-
#----------------------------------------------------------------------------
# Author: Niloy Saha
# Email: niloysaha.ns@gmail.com
# version ='1.0'
# ---------------------------------------------------------------------------
"""
Exporter which exports UPF PDR statistics from Free5gc UPF and writes them to /var/log/upf_stats.json
Depends on the libgtp5gnl project.
"""
import subprocess as subproc
import pathlib as path
import re
import socket as sock
import os
import time
import datetime
import json
import threading
import logging
from pprint import pformat

FORMAT = "%(filename)s: %(asctime)s %(levelname)s %(message)s"
logging.basicConfig(format=FORMAT, level=logging.INFO)


free5gc_dir   = path.Path("/free5gc/")
gtp5g_bin_dir = free5gc_dir / "libgtp5gnl/tools/"
hostname      = sock.gethostname()

UPF_STATS_FILE = "/var/log/upf_stats.json"
SEID = 0  # default SEID
UPF_IPv4_ADDR = None  # N3 interface IP
UPDATE_PERIOD = 1  # seconds

current_stats = []  # hold current stats


def get_active_pdr_ids():
    """
    get_active_pdr_ids: List[Int]
    Returns the list of PDR IDs installed in the GTP5G kernel module.
    """
    try:
        completed_proc = subproc.run([str(gtp5g_bin_dir / "gtp5g-tunnel"), "list", "pdr"], capture_output=True)
        stdout = completed_proc.stdout.decode("utf-8")
        pdr_info_line_matcher = re.compile(r"\[PDR No.[0-9]+ Info\]")
        matches = pdr_info_line_matcher.findall(stdout)
        pdrs = []
        for match in matches:
            pdr_id = match.split(".")[1].split(" ")[0]
            pdrs.append(int(pdr_id))
        return sorted(pdrs)
    except:
        logging.exception("Error in getting active PDRs")

def get_pdr_stats(pdr_id):
    """
    Returns statistics for a given PDR
    """

    try:
        # write PDR ID and interface name to proc file
        cmd = "echo 'upfgtp %d %d' > /proc/gtp5g/pdr" % (SEID, pdr_id)
        subproc.run(cmd, shell=True)
    except:
        logging.exception("Error in writing PDR ID and interface to proc file")

    try:
        # read the proc file
        cmd = ["cat", "/proc/gtp5g/pdr"]
        proc_read_stdout = subproc.run(cmd, capture_output=True).stdout.decode('utf-8')
    except:
        logging.exception("Error in reading proc file")

    # print(proc_read_stdout)

    ul_pkt_cnt_match = re.compile(r"UL Packet Count: (?P<count>[0-9]+)")
    dl_pkt_cnt_match = re.compile(r"DL Packet Count: (?P<count>[0-9]+)")
    ul_byte_cnt_match = re.compile(r"UL Byte Count: (?P<count>[0-9]+)")
    dl_byte_cnt_match = re.compile(r"DL Byte Count: (?P<count>[0-9]+)")

    ul_pkt_cnt = 0
    dl_pkt_cnt = 0
    ul_byte_cnt = 0
    dl_byte_cnt = 0

    try:
        ul_pkt_cnt = ul_pkt_cnt_match.search(proc_read_stdout).group("count")
        dl_pkt_cnt = dl_pkt_cnt_match.search(proc_read_stdout).group("count")
        ul_byte_cnt = ul_byte_cnt_match.search(proc_read_stdout).group("count")
        dl_byte_cnt = dl_byte_cnt_match.search(proc_read_stdout).group("count")
    except:
        logging.exception("Error in getting packet and byte counts!")

    timestamp = datetime.datetime.now()

    data = {
        "timestamp" : str(timestamp),
        "pdr_id": str(pdr_id),
        "pkt_count" : [ul_pkt_cnt, dl_pkt_cnt],
        "byte_count": [ul_byte_cnt, dl_byte_cnt]
    }

    json_string = json.dumps(data)
    current_stats.append(data)


def get_upf_ip_addr(iface):
    """
    get_upf_ip_addr: str -> str
    
    Returns the IP address of the interface. 
    Note: iface should be the name of the N3 interface on the UPF
    """
    ipv4_addr = os.popen('ip addr show %s' % iface).read().split("inet ")[1].split("/")[0]
    logging.info(f"UPF N3 IPv4 ADDR: {ipv4_addr}")

def get_container_name():
    container_name = os.popen('hostname | cut -d- -f1,2').read().strip()
    logging.info(f"CONTAINER: {container_name}")

# get metrics for all the active PDRs
def get_metrics():
    pdr_list = get_active_pdr_ids()
    for pdr_id in pdr_list:
        get_pdr_stats(pdr_id)

    logging.info(pformat(current_stats))

    current_stats_json = json.dumps(current_stats)
    with open(UPF_STATS_FILE, 'w') as outfile:
        outfile.write(current_stats_json)

    # clear current stats for next round of collection
    del current_stats[:]
    
def main():
    get_container_name()
    get_upf_ip_addr("n3")
    logging.info("Starting UPF stats collection ...")
    while True:
        try:
            get_metrics()
        except:
            logging.exception("Exception in getting metrics")
        # period between collection
        time.sleep(UPDATE_PERIOD)


if __name__ == "__main__":
    main()

