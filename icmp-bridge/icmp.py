# icmp.py

from scapy.all import sniff, send, IP, ICMP, Raw
import requests
import time
from concurrent.futures import ThreadPoolExecutor

# Define ICMP endpoint
BASE_URL = "http://51.255.80.207"
ICMP_ENDPOINT = f"{BASE_URL}/icmp_forwarding"
executor = ThreadPoolExecutor(max_workers=10)

def send_reply_packet(response_data):
    try:
        source_ip = response_data['source_ip']
        dest_ip = response_data['dest_ip']
        payload = bytes.fromhex(response_data['payload'])

        # ICMP-specific reply
        icmp_id = response_data['icmp_id']
        icmp_seq = response_data['icmp_seq']
        reply_packet = IP(src=source_ip, dst=dest_ip) / ICMP(type=0, id=icmp_id, seq=icmp_seq) / payload

        send(reply_packet)
        print(f"Sent ICMP reply to {dest_ip}")
    except Exception as e:
        print(f"Error sending ICMP reply: {e}")

def send_to_server(packet, data):
    try:
        start_time = time.time()
        response = requests.post(ICMP_ENDPOINT, json=data)
        elapsed_time = time.time() - start_time

        if response.status_code == 200:
            response_data = response.json()
            print(f"Received ICMP response: {response_data} | Time: {elapsed_time:.4f}s")
            send_reply_packet(response_data)
        elif response.status_code == 404:
            print(f"Destination not registered in database: {data['dest_ip']}")
        else:
            print(f"ERROR: Server returned status code {response.status_code}")
    except requests.RequestException as e:
        print(f"ERROR: Failed to send ICMP data: {e}")

def handle_packet(packet):
    if IP in packet and ICMP in packet and packet[ICMP].type == 8:  # Echo request
        data = {
            "source_ip": packet[IP].src,
            "dest_ip": packet[IP].dst,
            "payload": packet[Raw].load.hex() if Raw in packet else "",
            "icmp_id": packet[ICMP].id,
            "icmp_seq": packet[ICMP].seq
        }
        executor.submit(send_to_server, packet, data)

def start_sniffing(interface):
    print(f"Starting ICMP bridge on interface {interface}")
    sniff(filter="icmp", iface=interface, prn=handle_packet)

if __name__ == "__main__":
    start_sniffing("Brlx-ns-xcloud0")

