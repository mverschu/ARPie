
# ARP/DNS Poisoning and WPAD Exploitation Script

<img src="https://github.com/mverschu/ARPie/assets/69352107/a24746e2-dd2e-42ce-bc16-75ee1883c029" width="300" height="300" alt="ARPie">

## Overview
This script performs ARP poisoning, DNS spoofing, and WPAD exploitation. It is designed for network penetration testing and security analysis.

## Features
- **ARP Poisoning**: Redirect network traffic by spoofing ARP messages.
- **DNS Spoofing**: Intercept and modify DNS queries to redirect traffic.
- **WPAD Exploitation**: Serve a malicious WPAD file to configure a proxy server for the victim.

## Requirements
- Python 3.x
- Scapy
- Impacket
- Colorama

## Installation
1. Install required Python packages:
   ```bash
   pip install scapy impacket colorama
   ```

## Usage
```bash
python arp.py -i <interface> --target-ip <target_ip> [options]
```

### Arguments
- `-i, --interface`: Network interface to use (required)
- `--target-ip`: Target IP address (required)
- `--target-mac`: Target MAC address (optional, will be resolved if not provided)
- `--gateway-ip`: Gateway IP address (optional, will be resolved if not provided)
- `--gateway-mac`: Gateway MAC address (optional, will be resolved if not provided)
- `--attacker-ip`: Attacker's IP address (optional, will be resolved if not provided)
- `--proxy-port`: Port for the proxy server (optional)
- `--domain`: Domain to spoof (optional, e.g., domain.local)

### Example
```bash
# Auto
sudo python3 arp.py -i eth0 --target-ip 192.168.1.100 --proxy-port 8080 --domain example.com
# Manual (most trustable method)
sudo python3 arp.py --target-ip 192.168.100.183 --target-mac 52:54:00:9f:47:11 --gateway-ip 192.168.100.153 --gateway-mac 52:54:00:b0:a1:55 --attacker-ip 192.168.100.131 --domain wintastic.local -i eth0
```

## Functions

### get_mac(ip, iface)
Retrieves the MAC address for a given IP on the specified interface.

### get_gateway_ip()
Retrieves the IP address of the network gateway.

### get_local_ip(iface)
Retrieves the local IP address of the attacker machine.

### get_local_mac(iface)
Retrieves the local MAC address of the attacker machine.

### arp_poison(target_ip, target_mac, gateway_ip, gateway_mac, iface)
Performs ARP poisoning by sending spoofed ARP messages to the target and gateway.

### dns_spoof(pkt, attacker_ip, domain)
Intercepts and modifies DNS queries to redirect traffic to the attacker's IP address.

### start_dns_spoof(attacker_ip, domain, iface)
Starts DNS spoofing by sniffing for DNS queries on the specified interface.

### NTLMChallengePacket
Generates a custom NTLM challenge packet for NTLM authentication.

### ProxyHTTPRequestHandler
Handles HTTP requests to serve the malicious WPAD file and capture NTLM authentication attempts.

### start_proxy_server(port, attacker_ip, proxy_port)
Starts a proxy server on the specified port to serve the malicious WPAD file.

---

## Screenshots

#### Computer take over

![image](https://github.com/mverschu/ARPie/assets/69352107/2329f690-d3ed-4789-918c-b016ffc19605)

#### User take over

![image](https://github.com/mverschu/ARPie/assets/69352107/861cdb4b-0016-4525-b564-c4144ec49ff3)

By following the instructions above, you can utilize this script for network security testing and analysis. Ensure you have permission to test the network you are targeting.
