from scapy.all import sniff, send, IP, TCP, Raw
import requests
import time
from concurrent.futures import ThreadPoolExecutor

# Define TCP endpoint
BASE_URL = "http://51.255.80.207"
TCP_ENDPOINT = f"{BASE_URL}/tcp_forwarding"
executor = ThreadPoolExecutor(max_workers=10)

def send_reply_packet(response_data):
    try:
        # Prepare and log response data
        source_ip = response_data['source_ip']
        dest_ip = response_data['dest_ip']
        payload = bytes.fromhex(response_data['payload'])
        sport = response_data['sport']
        dport = response_data['dport']
        seq = response_data.get('seq', 0)
        ack = response_data.get('ack', 0)
        flags = response_data.get('flags', 'A')  # Default ACK flag
        
        print(f"Preparing to send reply packet to {dest_ip} with flags {flags}")
        reply_packet = IP(src=source_ip, dst=dest_ip) / TCP(
            sport=sport, dport=dport, seq=seq, ack=ack, flags=flags) / payload
        send(reply_packet)
        print(f"Sent TCP reply to {dest_ip}")
    except Exception as e:
        print(f"Error sending TCP reply: {e}")

def send_to_server(packet, data):
    try:
        # Log data being sent to the server
        print(f"Sending data to server: {data}")
        
        start_time = time.time()
        response = requests.post(TCP_ENDPOINT, json=data)
        elapsed_time = time.time() - start_time
        
        # Log response time
        print(f"Time taken for server response: {elapsed_time:.4f}s")
        
        if response.status_code == 200:
            response_data = response.json()
            print(f"Received TCP response: {response_data}")
            send_reply_packet(response_data)  # Send reply based on server response
        elif response.status_code == 404:
            print(f"Destination not registered in database: {data['dest_ip']}")
        else:
            print(f"ERROR: Server returned status code {response.status_code}")
    except requests.RequestException as e:
        print(f"ERROR: Failed to send TCP data: {e}")

def handle_packet(packet):
    if IP in packet and TCP in packet:
        print(f"Captured packet: {packet.summary()}")
        print(f"TCP Flags: {packet[TCP].flags}")  # Log the TCP flags
        
        # Prepare the packet data to send to the server
        data = {
            "source_ip": packet[IP].src,
            "dest_ip": packet[IP].dst,
            "payload": packet[Raw].load.hex() if Raw in packet else "",
            "sport": packet[TCP].sport,
            "dport": packet[TCP].dport,
            "seq": packet[TCP].seq,
            "ack": packet[TCP].ack,
            "flags": packet[TCP].flags
        }

        # Send the data to the server using a thread pool for concurrent requests
        executor.submit(send_to_server, packet, data)

def start_sniffing(interface):
    print(f"Starting TCP bridge on interface {interface}")
    sniff(filter="tcp", iface=interface, prn=handle_packet)

if __name__ == "__main__":
    start_sniffing("Brlx-ns-xcloud0")

