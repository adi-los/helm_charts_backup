# udp.py

from scapy.all import sniff, send, IP, UDP, Raw
import requests
import time
from concurrent.futures import ThreadPoolExecutor

# Define UDP endpoint
BASE_URL = "http://51.255.80.207"
UDP_ENDPOINT = f"{BASE_URL}/udp_forwarding"
executor = ThreadPoolExecutor(max_workers=10)

def send_reply_packet(response_data):
    try:
        source_ip = response_data['source_ip']
        dest_ip = response_data['dest_ip']
        payload = bytes.fromhex(response_data['payload'])
        
        sport = response_data['sport']
        dport = response_data['dport']
        reply_packet = IP(src=source_ip, dst=dest_ip) / UDP(sport=sport, dport=dport) / payload
        
        send(reply_packet)
        print(f"Sent UDP reply to {dest_ip}")
    except Exception as e:
        print(f"Error sending UDP reply: {e}")

def send_to_server(packet, data):
    try:
        start_time = time.time()
        response = requests.post(UDP_ENDPOINT, json=data)
        elapsed_time = time.time() - start_time

        if response.status_code == 200:
            response_data = response.json()
            print(f"Received UDP response: {response_data} | Time: {elapsed_time:.4f}s")
            send_reply_packet(response_data)
        elif response.status_code == 404:
            print(f"Destination not registered in database: {data['dest_ip']}")
        else:
            print(f"ERROR: Server returned status code {response.status_code}")
    except requests.RequestException as e:
        print(f"ERROR: Failed to send UDP data: {e}")

def handle_packet(packet):
    if IP in packet and UDP in packet:
        data = {
            "source_ip": packet[IP].src,
            "dest_ip": packet[IP].dst,
            "payload": packet[Raw].load.hex() if Raw in packet else "",
            "sport": packet[UDP].sport,
            "dport": packet[UDP].dport
        }
        executor.submit(send_to_server, packet, data)

def start_sniffing(interface):
    print(f"Starting UDP bridge on interface {interface}")
    sniff(filter="udp", iface=interface, prn=handle_packet)

if __name__ == "__main__":
    start_sniffing("Brlx-ns-xcloud0")

