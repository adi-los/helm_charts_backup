package main

import (
    "bytes"
    "encoding/hex"
    "encoding/json"
    "fmt"
    "log"
    "net/http"
    "sync"
    "time"

    "github.com/google/gopacket"
    "github.com/google/gopacket/layers"
    "github.com/google/gopacket/pcap"
)

// Define endpoints
const (
    baseURL       = "http://51.255.80.207"
    icmpEndpoint  = baseURL + "/icmp_forwarding"
    tcpEndpoint   = baseURL + "/tcp_forwarding"
    udpEndpoint   = baseURL + "/udp_forwarding"
    iface         = "Brlx-ns-xcloud0"
    maxGoroutines = 10
)

var httpClient = &http.Client{
    Timeout: time.Second * 5,
}

type PacketData struct {
    SourceIP string `json:"source_ip"`
    DestIP   string `json:"dest_ip"`
    Payload  string `json:"payload"`
    ICMPID   uint16 `json:"icmp_id,omitempty"`
    ICMPSeq  uint16 `json:"icmp_seq,omitempty"`
    Sport    uint16 `json:"sport,omitempty"`
    Dport    uint16 `json:"dport,omitempty"`
    Seq      uint32 `json:"seq,omitempty"`
    Ack      uint32 `json:"ack,omitempty"`
    Flags    string `json:"flags,omitempty"`
}

func sendToServer(data PacketData, protocol string) {
    var endpoint string
    switch protocol {
    case "ICMP":
        endpoint = icmpEndpoint
    case "TCP":
        endpoint = tcpEndpoint
    case "UDP":
        endpoint = udpEndpoint
    default:
        log.Printf("Unknown protocol: %s", protocol)
        return
    }

    jsonData, err := json.Marshal(data)
    if err != nil {
        log.Printf("Error encoding JSON: %v", err)
        return
    }

    resp, err := httpClient.Post(endpoint, "application/json", bytes.NewBuffer(jsonData))
    if err != nil {
        log.Printf("HTTP error for %s data: %v", protocol, err)
        return
    }
    defer resp.Body.Close()

    if resp.StatusCode == http.StatusOK {
        log.Printf("Received successful response for %s packet.", protocol)
    } else {
        log.Printf("Server returned status %d for %s packet.", resp.StatusCode, protocol)
    }
}

func handlePacket(packet gopacket.Packet) {
    ipLayer := packet.Layer(layers.LayerTypeIPv4)
    if ipLayer == nil {
        return
    }
    ip, _ := ipLayer.(*layers.IPv4)

    var data PacketData
    data.SourceIP = ip.SrcIP.String()
    data.DestIP = ip.DstIP.String()

    if appLayer := packet.ApplicationLayer(); appLayer != nil {
        data.Payload = hex.EncodeToString(appLayer.Payload())
    }

    if icmpLayer := packet.Layer(layers.LayerTypeICMPv4); icmpLayer != nil {
        icmp, _ := icmpLayer.(*layers.ICMPv4)
        if icmp.TypeCode.Type() == layers.ICMPv4TypeEchoRequest {
            data.ICMPID = icmp.Id
            data.ICMPSeq = icmp.Seq
            go sendToServer(data, "ICMP")
        }
    } else if tcpLayer := packet.Layer(layers.LayerTypeTCP); tcpLayer != nil {
        tcp, _ := tcpLayer.(*layers.TCP)
        data.Sport = uint16(tcp.SrcPort)
        data.Dport = uint16(tcp.DstPort)
        data.Seq = tcp.Seq
        data.Ack = tcp.Ack
        data.Flags = tcpFlagsToString(tcp)
        go sendToServer(data, "TCP")
    } else if udpLayer := packet.Layer(layers.LayerTypeUDP); udpLayer != nil {
        udp, _ := udpLayer.(*layers.UDP)
        data.Sport = uint16(udp.SrcPort)
        data.Dport = uint16(udp.DstPort)
        go sendToServer(data, "UDP")
    }
}

// tcpFlagsToString creates a string representation of TCP flags
func tcpFlagsToString(tcp *layers.TCP) string {
    var flags []string
    if tcp.SYN {
        flags = append(flags, "SYN")
    }
    if tcp.ACK {
        flags = append(flags, "ACK")
    }
    if tcp.FIN {
        flags = append(flags, "FIN")
    }
    if tcp.RST {
        flags = append(flags, "RST")
    }
    if tcp.PSH {
        flags = append(flags, "PSH")
    }
    if tcp.URG {
        flags = append(flags, "URG")
    }
    return fmt.Sprintf("%v", flags)
}

func startSniffing(wg *sync.WaitGroup) {
    defer wg.Done()

    handle, err := pcap.OpenLive(iface, 1600, true, pcap.BlockForever)
    if err != nil {
        log.Fatalf("Error opening device %s: %v", iface, err)
    }
    defer handle.Close()

    packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
    for packet := range packetSource.Packets() {
        handlePacket(packet)
    }
}

func main() {
    var wg sync.WaitGroup
    wg.Add(maxGoroutines)
    for i := 0; i < maxGoroutines; i++ {
        go startSniffing(&wg)
    }
    fmt.Printf("Starting network bridge on interface %s\n", iface)
    fmt.Println("Waiting for packets... Replies will be sent after receiving response from destination")
    wg.Wait()
}

