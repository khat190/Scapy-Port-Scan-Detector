import sys
import time
import threading
from collections import defaultdict
from queue import Queue
from scapy.all import sniff, IP, TCP, UDP, ICMP

packet_queue = Queue()
running = True

ip_tracker = defaultdict(list)
alerted_ips = set()

SCAN_THRESHOLD = 5
TIME_WINDOW = 10


def packet_producer(interface="lo"):
    def enqueue_packet(packet):
        packet_queue.put(packet)

    print("[*]Producer started: Sniffing live traffic..")
    sniff(iface=interface, prn=enqueue_packet, store=0)

def detect_port_scan(src_ip, dst_port):
    current_time = time.time()
    ip_tracker[src_ip].append((current_time, dst_port))
    ip_tracker[src_ip] = [
        (ts, port) for ts, port in ip_tracker[src_ip]
        if current_time - ts <= TIME_WINDOW
    ]
    recent_ports = {port for ts, port in ip_tracker[src_ip]}

    if len(recent_ports) >= SCAN_THRESHOLD and src_ip not in alerted_ips:
        print("\n" + "!" * 60)
        print(f"[ALERT] POTENTIAL PORT SCAN DETECTED!")
        print(f" Source IP       : {src_ip}")
        print(f" Unique Ports    : {len(recent_ports)} (Ports: {sorted(list(recent_ports))})")
        print(f" Time Window     : Last {TIME_WINDOW} seconds")
        print("!" * 60 + "\n")

        alerted_ips.add(src_ip)

def packet_consumer():
    print("[*]Consumer started: Processing queue...")

    while running or not packet_queue.empty():
        if not packet_queue.empty():
            packet = packet_queue.get()
            process_packet(packet)
            packet_queue.task_done()
        else:
            time.sleep(0.01)


def process_packet(packet):
    if IP in packet:
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst
        protocol = "OTHER"

        if TCP in packet:
            protocol = "TCP"
            src_port = packet[TCP].sport
            dst_port = packet[TCP].dport

        if packet[TCP].flag == "S":
            detect_port_scan(src_ip, dst_port)
            
            print(f"[+]{protocol} | {src_ip} : {src_port} -> {dst_ip} {dst_port}")
        elif UDP in packet:
            protocol = "UDP"
            src_port = packet[UDP].sport
            dst_port = packet[UDP].dport
            detect_port_scan(src_ip, dst_port)
            print(f"[+]{protocol} | {src_ip} : {src_port} -> {dst_ip} -> {dst_port}")
        elif ICMP in packet:
            protocol = "ICMP"
            
            print(f"[+]{protocol} | {src_ip} -> {dst_ip}")

# def start_sniffing(interface=None, count=10):
#     print(f"[*]Starting live sniffing (capturing {count} packets...)")
#     sniff(iface=interface, prn=process_packet,count=count,store=0)
#     print(f"[*]Sniffing Complete")

if __name__ == "__main__":
    try:
        consumer_thread = threading.Thread(target=packet_consumer, daemon=True)
        consumer_thread.start()
        packet_producer()
    except KeyboardInterrupt:
        print("\n[*]Stopping live IDS sniffer..")
        running =False
        sys.exit(0)
    
        
