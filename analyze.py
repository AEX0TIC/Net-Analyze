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

        #Display packet info in rich table 
        table = Table(show_header=True,header_style="bold cyan")
        table.add_column("Protocol", style="bold")
        table.add_column("Source IP")
        table.add_column("Destination IP")
        table.add_column("Length", justify="right")
        table.add_row(proto,src_ip, dst_ip, str(length))
        console.print(table)
    
        #Record timestamp for plotting 
        with lock:
            now = int(time.time() - start_time)
        if len(time_stamps) == 0 or now != time_stamps[-1]:
            time_stamps.append(now)
            packet_counts.append(1)
        else:
            packet_counts[-1] += 1

def start_sniffing():
    sniff(prn=packet_callback, store=0)

def update_plot(frame):
    with lock:
        plt.cla()
        plt.title("Live Packet Count (Packets/sec)")
        plt.xlabel("Time (s)")
        plt.ylabel("Packets")

        if time_stamps and packet_counts:
            plt.plot(time_stamps, packet_counts, color="blue")

        plt.tight_layout()

def main():
    console.print("[bold green]Starting Network Traffic Analyzer...[/bold green]")
    console.print("[bold yellow]Press CTRL+C to stop.[/bold yellow]")

    thread = threading.Thread(target=start_sniffing)
    thread.daemon = True
    thread.start()

    ani = FuncAnimation(plt.gcf(), update_plot, interval=1000, cache_frame_data=False)
    plt.show()

if __name__ == "__main__":
    main()