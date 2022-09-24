#!/usr/bin/env python3.8
# -*- coding: utf-8 -*-
#----------------------------------------------------------------------------
# Author: Niloy Saha
# Email: niloysaha.ns@gmail.com
# version ='1.0'
# ---------------------------------------------------------------------------
"""
Prometheus exporter which exports UPF PDR statistics from Free5gc UPF.
Depends on the libgtp5gnl project.
"""
import prometheus_client as prom
import subprocess as subproc
import pathlib as path
import re
import socket as sock
import os
import time


free5gc_dir   = path.Path("/free5gc/")
gtp5g_bin_dir = free5gc_dir / "libgtp5gnl/tools/"
hostname      = sock.gethostname()


SEID = 0  # default SEID
UPF_IPv4_ADDR = None  # N3 interface IP
UPDATE_PERIOD = 1  # seconds
PDR_PACKET_COUNT = prom.Gauge('pdr_packet_count', 
                     'Cumulative packet counts per PDR', 
                     ['pdr_id', 'direction'])
PDR_BYTE_COUNT = prom.Gauge('pdr_byte_count', 
                     'Cumulative byte counts per PDR', 
                     ['pdr_id', 'direction'])

prom.REGISTRY.unregister(prom.PROCESS_COLLECTOR)
prom.REGISTRY.unregister(prom.PLATFORM_COLLECTOR)
prom.REGISTRY.unregister(prom.GC_COLLECTOR)

class PDRStats:
    """
    Represent PDR statistics including packet and byte counts
    """
    def __init__(self, pdr_id) -> None:
        self.pdr_id = pdr_id
        self.ul_pkt_cnt = 0
        self.dl_pkt_cnt = 0
        self.ul_byte_cnt = 0
        self.dl_byte_cnt = 0

    def __repr__(self) -> str:
        return f'PDR ID: {self.pdr_id} \
        \n UL PACKET COUNT: {self.ul_pkt_cnt} \
        \n UL BYTE COUNT: {self.ul_byte_cnt} \
        \n DL PACKET COUNT: {self.dl_pkt_cnt} \
        \n DL BYTE COUNT: {self.dl_byte_cnt}'

def get_active_pdr_ids():
    """
    get_active_pdr_ids: List[Int]
    Returns the list of PDR IDs installed in the GTP5G kernel module.
    """
    completed_proc = subproc.run([str(gtp5g_bin_dir / "gtp5g-tunnel"), "list", "pdr"], capture_output=True)
    stdout = completed_proc.stdout.decode("utf-8")
    pdr_info_line_matcher = re.compile(r"\[PDR No.[0-9]+ Info\]")
    matches = pdr_info_line_matcher.findall(stdout)
    pdrs = []
    for match in matches:
        pdr_id = match.split(".")[1].split(" ")[0]
        pdrs.append(int(pdr_id))
    return sorted(pdrs)

def get_pdr_stats(pdr_id):
    """
    get_pdr_stats: int -> (PDRStats)
    Returns statistics for a given PDR
    """

    # write PDR ID and interface name to proc file
    cmd = "echo 'upfgtp %d %d' > /proc/gtp5g/pdr" % (SEID, pdr_id)
    subproc.run(cmd, shell=True)

    # read the proc file
    cmd = ["cat", "/proc/gtp5g/pdr"]
    proc_read_stdout = subproc.run(cmd, capture_output=True).stdout.decode('utf-8')

    # print(proc_read_stdout)

    ul_pkt_cnt_match = re.compile(r"UL Packet Count: (?P<count>[0-9]+)")
    dl_pkt_cnt_match = re.compile(r"DL Packet Count: (?P<count>[0-9]+)")
    ul_byte_cnt_match = re.compile(r"UL Byte Count: (?P<count>[0-9]+)")
    dl_byte_cnt_match = re.compile(r"DL Byte Count: (?P<count>[0-9]+)")

    ul_pkt_cnt = ul_pkt_cnt_match.search(proc_read_stdout).group("count")
    dl_pkt_cnt = dl_pkt_cnt_match.search(proc_read_stdout).group("count")
    ul_byte_cnt = ul_byte_cnt_match.search(proc_read_stdout).group("count")
    dl_byte_cnt = dl_byte_cnt_match.search(proc_read_stdout).group("count")

    # print(f'PDR ID: {pdr_id} \
    #     \n UL PACKET COUNT: {ul_pkt_cnt} \
    #     \n UL BYTE COUNT: {ul_byte_cnt} \
    #     \n DL PACKET COUNT: {dl_pkt_cnt} \
    #     \n DL BYTE COUNT: {dl_byte_cnt}'
    # )

    PDR_PACKET_COUNT.labels(pdr_id=str(pdr_id), direction="uplink").set(ul_pkt_cnt)
    PDR_PACKET_COUNT.labels(pdr_id=str(pdr_id), direction="downlink").set(dl_pkt_cnt)

    PDR_BYTE_COUNT.labels(pdr_id=str(pdr_id), direction="uplink").set(ul_byte_cnt)
    PDR_BYTE_COUNT.labels(pdr_id=str(pdr_id), direction="downlink").set(dl_byte_cnt)

def get_upf_ip_addr(iface):
    """
    get_upf_ip_addr: str -> str
    
    Returns the IP address of the interface. 
    Note: iface should be the name of the N3 interface on the UPF
    """
    ipv4_addr = os.popen('ip addr show %s' % iface).read().split("inet ")[1].split("/")[0]
    print(f"UPF N3 IPv4 ADDR: {ipv4_addr}")

def get_container_name():
    container_name = os.popen('hostname | cut -d- -f1,2').read().strip()
    print(f"CONTAINER: {container_name}")

def get_metrics():
    pdr_list = get_active_pdr_ids()
    for pdr_id in pdr_list:
        get_pdr_stats(pdr_id)


def main():
    get_container_name()
    get_upf_ip_addr("n3")

    print("Starting Prometheus server ...")
    prom.start_http_server(9000)
    while True:
        get_metrics()
        # period between collection
        time.sleep(UPDATE_PERIOD)


if __name__ == "__main__":
    main()

