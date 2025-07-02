from scapy.all import sniff, IP, TCP, UDP, ICMP
from rich.console import Console
from rich.table import Table

import matplotlib.pyplot as plt 
from matplotlib.animation import FuncAnimation
import threading
import time 

console = Console()

packet_counts = []
timestamps = []
start_time = time.time()

#Lock for thread-safe access to data
lock = threading.Lock()

def packet_callback(packet):
    proto = "OTHER"

    if IP in packet:
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst
        length = len(packet)

        if TCP in packet:
            proto = "TCP"
        elif UDP is packet:
            proto = "UDP"
        elif ICMP is packet:
            proto = "ICMP"
        else:
            proto = "IP"

        table = Table(show_header=True,header_style="bold cyan")
        table.add_column("Protocol", style="bold")
        table.add_column("Source IP")
        table.add_column("Destination IP")
    