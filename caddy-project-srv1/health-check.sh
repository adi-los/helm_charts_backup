#!/bin/bash
GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
NC='\033[0m'

# Sample JSON payload with hex-encoded test payload (74657374 is "test" in hex)
PAYLOAD='{
  "source_ip": "192.168.1.1",
  "dest_ip": "192.168.1.2",
  "icmp_id": 1234,
  "icmp_seq": 1,
  "payload": "74657374"
}'

echo "Starting debug tests..."
echo "----------------------"

# Check if Caddy is running
echo -n "1. Checking Caddy container status: "
if docker ps | grep caddy-proxy > /dev/null; then
    echo -e "${GREEN}Running${NC}"
    docker ps | grep caddy-proxy
else
    echo -e "${RED}Not running${NC}"
fi

# Test direct backend access
echo -e "\n2. Testing direct backend access:"
echo -n "   ICMP forwarding (8080): "
curl -s -X POST -H "Content-Type: application/json" -d "$PAYLOAD" \
    -o /dev/null -w "%{http_code}" http://51.255.80.207:8080/icmp_forwarding
echo -e " ${YELLOW}(direct access)${NC}"

echo -n "   All ICMP (5520): "
curl -s -X POST -H "Content-Type: application/json" -d "$PAYLOAD" \
    -o /dev/null -w "%{http_code}" http://51.255.80.207:5520/all_icmp
echo -e " ${YELLOW}(direct access)${NC}"

# Test through Caddy with verbose output
echo -e "\n3. Testing through Caddy (verbose):"
echo -e "${YELLOW}ICMP forwarding endpoint:${NC}"
curl -v -X POST -H "Content-Type: application/json" \
    -d "$PAYLOAD" "http://51.255.80.207/icmp_forwarding?namespace=test" 2>&1

echo -e "\n${YELLOW}All ICMP endpoint:${NC}"
curl -v -X POST -H "Content-Type: application/json" \
    -d "$PAYLOAD" "http://51.255.80.207/all_icmp?namespace=test" 2>&1

# Check Caddy logs
echo -e "\n4. Last 10 Caddy log entries:"
docker compose logs --tail=10 caddy

echo -e "\nDebug test complete!"
