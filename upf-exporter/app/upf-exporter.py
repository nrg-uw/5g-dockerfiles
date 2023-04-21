#!/usr/bin/python3
import os
import re
import time
import subprocess
import logging
from prometheus_client import start_http_server, Gauge, REGISTRY, PLATFORM_COLLECTOR, PROCESS_COLLECTOR, GC_COLLECTOR

logging.basicConfig(level=logging.INFO,
                    format='%(asctime)s | %(message)s', datefmt='%Y-%m-%d %H:%M:%S')

PDR_INFO_LINE_MATCHER = re.compile(r"\[PDR No\.(\d+) SEID (\d+) Info\]")

# Define Prometheus metrics
PACKET_COUNT = Gauge('pdr_packet_count', 'Number of packets', [
                     'seid', 'pdrid', 'n3_ip', 'n4_ip', 'direction'])
BYTE_COUNT = Gauge('pdr_byte_count', 'Number of bytes', [
                   'seid', 'pdrid', 'n3_ip', 'n4_ip', 'direction'])

SERVER_PORT = int(os.environ.get('SERVER_PORT', '9000'))
SLEEP_INTERVAL = int(os.environ.get('SLEEP_INTERVAL', '10'))

REGISTRY.unregister(PROCESS_COLLECTOR)
REGISTRY.unregister(PLATFORM_COLLECTOR)
REGISTRY.unregister(GC_COLLECTOR)


def get_active_pdrs():
    """
    Returns a list of active PDRs, each represented by a dictionary containing the PDR ID and SEID.
    Extracts the information from the output of the 'gtp5g-tunnel list pdr' command using regex.
    The list is sorted by the PDR ID in ascending order. Returns an empty list on error.
    """
    try:
        completed_proc = subprocess.run(
            ["/app/libgtp5gnl/tools/gtp5g-tunnel", "list", "pdr"], capture_output=True, text=True)
        stdout = completed_proc.stdout

        active_pdrs = []

        for match in PDR_INFO_LINE_MATCHER.finditer(stdout):
            pdrid, seid = match.groups()
            active_pdrs.append({'pdrid': int(pdrid), 'seid': int(seid)})

        active_pdrs_sorted = sorted(active_pdrs, key=lambda d: d['pdrid'])
        return active_pdrs_sorted

    except subprocess.CalledProcessError as e:
        logging.warning(f"Error in getting active PDRs: {e}")
        return []


def get_pdr_stats(seid, pdrid):
    """
    Returns a dictionary containing packet and byte counts (both UL and DL) for a given PDR.

    Parameters:
    seid (int): the SEID of the PDR
    pdrid (int): the ID of the PDR

    Returns:
    dict: a dictionary containing packet and byte counts (both UL and DL) for the PDR
    """
    try:

        with open('/proc/gtp5g/pdr', 'w') as f:
            f.write(f'upfgtp {seid} {pdrid}\n')

        # Get the PDR information from the proc interface
        completed_proc = subprocess.run(
            ["cat", "/proc/gtp5g/pdr"], capture_output=True, text=True, check=True)
        stdout = completed_proc.stdout

        # Parse the packet and byte counts from the output
        ul_packet_count_match = re.search(r"UL Packet Count: (\d+)", stdout)
        dl_packet_count_match = re.search(r"DL Packet Count: (\d+)", stdout)
        ul_byte_count_match = re.search(r"UL Byte Count: (\d+)", stdout)
        dl_byte_count_match = re.search(r"DL Byte Count: (\d+)", stdout)

        # Create and return the dictionary of PDR statistics
        pdr_stats = {
            'seid': seid,
            'pdrid': pdrid,
            'ul_packet_count': int(ul_packet_count_match.group(1)),
            'dl_packet_count': int(dl_packet_count_match.group(1)),
            'ul_byte_count': int(ul_byte_count_match.group(1)),
            'dl_byte_count': int(dl_byte_count_match.group(1)),
            'timestamp': int(time.time()),
            'n3_ip': get_upf_ip_addr('n3'),
            'n4_ip': get_upf_ip_addr('n4')
        }
        return pdr_stats

    except IOError as e:
        logging.error(f"Error writing to proc file: {e}")

    except subprocess.CalledProcessError as e:
        logging.error(
            f"Error in getting PDR stats for SEID {seid} and PDRID {pdrid}: {e}")
        return {}


def get_upf_ip_addr(iface: str) -> str:
    """
    Returns the IP address of the interface.
    """
    try:
        output = subprocess.check_output(["ip", "addr", "show", iface])
    except subprocess.CalledProcessError as e:
        raise RuntimeError(
            f"Command {e.cmd} failed with error {e.returncode}: {e.stderr}")
    except Exception as e:
        raise RuntimeError(f"Error executing command: {e}")

    ipv4_regex = r'inet ([0-9]+\.[0-9]+\.[0-9]+\.[0-9]+)'
    match = re.search(ipv4_regex, output.decode())
    if match:
        return match.group(1)
    else:
        raise RuntimeError("IP address not found in output")


def log_data(data):
    for log in data:
        packet_counts = f"({log['ul_packet_count']},{log['dl_packet_count']})"
        byte_counts = f"({log['ul_byte_count']},{log['dl_byte_count']})"
        log_str = f"seid={log['seid']}|pdrid={log['pdrid']}|packet_counts={packet_counts}|byte_counts={byte_counts}|n3_ip={log['n3_ip']}|n4_ip={log['n4_ip']}"
        logging.info(log_str)


def get_active_pdrs_stats():
    """
    Returns a list of dictionaries containing the PDR statistics for all active PDRs.
    Each dictionary contains 'pdrid', 'seid', 'ul_packet_count', 'dl_packet_count', 'ul_byte_count',
    and 'dl_byte_count' keys.
    """
    active_pdrs = get_active_pdrs()
    pdr_stats = []
    for pdr in active_pdrs:
        stats = get_pdr_stats(pdr['seid'], pdr['pdrid'])
        pdr_stats.append(stats)
    return pdr_stats


def main():
    start_http_server(SERVER_PORT)
    logging.info("Starting Prometheus server ...")
    while True:
        try:
            pdr_stats = get_active_pdrs_stats()
            if not pdr_stats:
                logging.warning(f"No PDR statistics found ...")
            log_data(pdr_stats)
            for pdr in pdr_stats:
                ul_label = {'seid': pdr['seid'], 'pdrid': pdr['pdrid'],
                            'n3_ip': pdr['n3_ip'], 'n4_ip': pdr['n4_ip'], 'direction': 'UL'}
                dl_label = {'seid': pdr['seid'], 'pdrid': pdr['pdrid'],
                            'n3_ip': pdr['n3_ip'], 'n4_ip': pdr['n4_ip'], 'direction': 'DL'}
                PACKET_COUNT.labels(**ul_label).set(pdr['ul_packet_count'])
                PACKET_COUNT.labels(**dl_label).set(pdr['dl_packet_count'])
                BYTE_COUNT.labels(**ul_label).set(pdr['ul_byte_count'])
                BYTE_COUNT.labels(**dl_label).set(pdr['dl_byte_count'])
            time.sleep(SLEEP_INTERVAL)
        except Exception as e:
            logging.error(e)


if __name__ == "__main__":
    main()
