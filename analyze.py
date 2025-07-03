from scapy.all import sniff, IP, TCP, UDP, ICMP
from rich.console import Console
from rich.table import Table

import matplotlib.pyplot as plt
from matplotlib.animation import FuncAnimation
import threading
import time
from scapy.utils import wrpcap
import atexit

console = Console()

# Global shared data
packet_counts = []
time_stamps = []
start_time = time.time()
lock = threading.Lock()
captured_packets = []

# Handle graceful exit to save .pcap
def save_pcap():
    if captured_packets:
        wrpcap("captured_traffic.pcap", captured_packets)
        console.print("[bold green]Saved packets to captured_traffic.pcap[/bold green]")

atexit.register(save_pcap)

# Callback to process each packet
def packet_callback(packet):
    global packet_counts, time_stamps, captured_packets

    if IP in packet:
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst
        length = len(packet)
        proto = "OTHER"

        if TCP in packet:
            proto = "TCP"
        elif UDP in packet:
            proto = "UDP"
        elif ICMP in packet:
            proto = "ICMP"
        else:
            proto = "IP"

        # Print packet info
        table = Table(show_header=True, header_style="bold cyan")
        table.add_column("Protocol", style="bold")
        table.add_column("Source IP")
        table.add_column("Destination IP")
        table.add_column("Length", justify="right")
        table.add_row(proto, src_ip, dst_ip, str(length))
        console.print(table)

        # Save packet
        captured_packets.append(packet)

        # For plotting
        with lock:
            now = int(time.time() - start_time)
            if len(time_stamps) == 0 or now != time_stamps[-1]:
                time_stamps.append(now)
                packet_counts.append(1)
            else:
                packet_counts[-1] += 1

# Sniff in a thread
def start_sniffing():
    sniff(prn=packet_callback, store=0)

# Live plot function
def update_plot(frame):
    global packet_counts, time_stamps
    with lock:
        plt.cla()
        plt.title("Live Packet Count (Packets/sec)")
        plt.xlabel("Time (s)")
        plt.ylabel("Packets")

        if time_stamps and packet_counts:
            plt.plot(time_stamps, packet_counts, color='blue')
        else:
            plt.plot([0], [0], color='white')  # dummy plot

        plt.tight_layout()

# Main
def main():
    console.print("[bold green]Starting Network Traffic Analyzer...[/bold green]")
    console.print("[bold yellow]Press CTRL+C to stop.[/bold yellow]")

    sniff_thread = threading.Thread(target=start_sniffing)
    sniff_thread.daemon = True
    sniff_thread.start()

    ani = FuncAnimation(plt.gcf(), update_plot, interval=1000, cache_frame_data=False)
    plt.show()

if __name__ == "__main__":
    main()
