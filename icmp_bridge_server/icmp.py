#!/usr/bin/env python3
import logging
from flask import Flask, request, jsonify
import subprocess
import json
import binascii
import re
from scapy.all import IP, ICMP, TCP, UDP, Raw

app = Flask(__name__)

def forward_packet_in_namespace(protocol, data, namespace):
    try:
        interface = f"veth-{namespace}"
        dest_ip = data['dest_ip']

        if protocol == "ICMP":
            cmd = [
                'ip', 'netns', 'exec', namespace,
                'ping', '-c', '1', '-W', '2',
                '-s', str(len(bytes.fromhex(data['payload']))),
                '-p', data['payload'],
                '-I', interface,
                dest_ip
            ]
        elif protocol in ["TCP", "UDP"]:
            # Use netcat for TCP/UDP forwarding
            nc_cmd = 'nc' if protocol == "TCP" else 'nc -u'
            cmd = [
                'ip', 'netns', 'exec', namespace,
                'bash', '-c',
                f'echo "{data["payload"]}" | {nc_cmd} -w 2 {dest_ip} {data["dport"]}'
            ]

        result = subprocess.run(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=3
        )

        if result.returncode == 0:
            return {
                'success': True,
                'payload': data['payload'],
                'source_ip': data['dest_ip'],
                'dest_ip': data['source_ip'],
                **{k:v for k,v in data.items() if k not in ['source_ip', 'dest_ip', 'payload']}
            }

        return {
            'success': False,
            'error': f'Failed to forward {protocol} packet'
        }

    except Exception as e:
        logging.error(f"Error in namespace operation: {str(e)}")
        return {
            'success': False,
            'error': str(e)
        }

@app.route('/all_icmp', methods=['POST'])
def handle_icmp():
    return handle_protocol("ICMP")

@app.route('/all_tcp', methods=['POST'])
def handle_tcp():
    return handle_protocol("TCP")

@app.route('/all_udp', methods=['POST'])
def handle_udp():
    return handle_protocol("UDP")

def handle_protocol(protocol):
    try:
        data = request.json
        namespace = data.get('namespace_linux') or request.headers.get('X-Namespace') or "ns-xcloud0"

        result = forward_packet_in_namespace(protocol, data, namespace)

        if result['success']:
            print(f"Successfully forwarded {protocol} through namespace: {result}")
            return jsonify(result)
        else:
            return jsonify({'error': result['error']}), 500

    except Exception as e:
        logging.error(f"Error handling {protocol} request: {str(e)}")
        return jsonify({'error': str(e)}), 500

if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
    app.run(host='51.255.80.207', port=5520)

