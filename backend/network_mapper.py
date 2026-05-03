"""
Network Mapper Module
Discovers live devices on the LAN using ARP ping (Scapy)
then port-scans each discovered host for common open ports.
Falls back to socket-based ping sweep if Scapy is unavailable.
"""

import socket
import threading
import ipaddress
import time
import platform
import subprocess
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed

# ─── Config ───────────────────────────────────────────────────────────────────

COMMON_PORTS = [
    21, 22, 23, 25, 53, 80, 110, 135, 139, 143,
    443, 445, 3306, 3389, 5432, 5900, 6379, 8080, 8443, 27017
]

PORT_SERVICES = {
    21: 'FTP', 22: 'SSH', 23: 'Telnet', 25: 'SMTP',
    53: 'DNS', 80: 'HTTP', 110: 'POP3', 135: 'RPC',
    139: 'NetBIOS', 143: 'IMAP', 443: 'HTTPS', 445: 'SMB',
    3306: 'MySQL', 3389: 'RDP', 5432: 'PostgreSQL',
    5900: 'VNC', 6379: 'Redis', 8080: 'HTTP-Alt',
    8443: 'HTTPS-Alt', 27017: 'MongoDB'
}

SCAN_TIMEOUT = 0.5       # seconds per port
ARP_TIMEOUT  = 2         # seconds for ARP sweep
MAX_WORKERS  = 50        # parallel port scan threads


# ─── Public API ───────────────────────────────────────────────────────────────

def get_local_network() -> str:
    """Auto-detect the local subnet (e.g. 192.168.1.0/24)"""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(('8.8.8.8', 80))
        local_ip = s.getsockname()[0]
        s.close()
        # Assume /24 subnet
        parts = local_ip.rsplit('.', 1)
        return f"{parts[0]}.0/24"
    except Exception:
        return '192.168.1.0/24'


def get_local_ip() -> str:
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(('8.8.8.8', 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except Exception:
        return '127.0.0.1'


def scan_network(subnet: str = None, progress_callback=None) -> list:
    """
    Full network scan: discover hosts then port-scan each.
    Returns list of host dicts.
    progress_callback(percent, message) called during scan.
    """
    if not subnet:
        subnet = get_local_network()

    if progress_callback:
        progress_callback(5, f'Scanning subnet {subnet}')

    # Step 1: Host discovery
    live_hosts = _discover_hosts(subnet, progress_callback)

    if progress_callback:
        progress_callback(50, f'Found {len(live_hosts)} hosts — scanning ports')

    # Step 2: Port scan each live host
    results = []
    for i, host in enumerate(live_hosts):
        open_ports = _scan_ports(host['ip'])
        host['open_ports'] = open_ports
        host['risk'] = _assess_risk(open_ports)
        results.append(host)
        if progress_callback:
            pct = 50 + int((i + 1) / max(len(live_hosts), 1) * 45)
            progress_callback(pct, f'Scanned {host["ip"]} — {len(open_ports)} open ports')

    if progress_callback:
        progress_callback(100, f'Scan complete — {len(results)} devices found')

    return results


# ─── Host Discovery ───────────────────────────────────────────────────────────

def _discover_hosts(subnet: str, progress_callback=None) -> list:
    """Try ARP first (needs Scapy), fall back to ICMP ping sweep"""
    try:
        return _arp_scan(subnet)
    except Exception:
        return _ping_sweep(subnet, progress_callback)


def _arp_scan(subnet: str) -> list:
    """ARP ping sweep — fast and reliable, needs Scapy + root"""
    from scapy.all import ARP, Ether, srp

    arp = ARP(pdst=subnet)
    ether = Ether(dst='ff:ff:ff:ff:ff:ff')
    packet = ether / arp

    answered, _ = srp(packet, timeout=ARP_TIMEOUT, verbose=False)

    hosts = []
    for sent, received in answered:
        hosts.append({
            'ip': received.psrc,
            'mac': received.hwsrc,
            'hostname': _resolve_hostname(received.psrc),
            'vendor': _mac_vendor(received.hwsrc),
            'method': 'ARP',
        })
    return hosts


def _ping_sweep(subnet: str, progress_callback=None) -> list:
    """Socket-based TCP connect sweep — works without root"""
    network = ipaddress.ip_network(subnet, strict=False)
    hosts = list(network.hosts())
    live = []
    lock = threading.Lock()

    def check_host(ip_obj):
        ip = str(ip_obj)
        # Try connecting to port 80 or 22 as a "ping"
        for port in [80, 22, 443, 135]:
            try:
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s.settimeout(0.3)
                result = s.connect_ex((ip, port))
                s.close()
                if result == 0:
                    with lock:
                        live.append({
                            'ip': ip,
                            'mac': 'N/A',
                            'hostname': _resolve_hostname(ip),
                            'vendor': 'Unknown',
                            'method': 'TCP',
                        })
                    return
            except Exception:
                pass

    with ThreadPoolExecutor(max_workers=MAX_WORKERS) as ex:
        futures = {ex.submit(check_host, ip): ip for ip in hosts}
        done = 0
        for future in as_completed(futures):
            done += 1
            if progress_callback and done % 10 == 0:
                pct = int(done / len(hosts) * 45)
                progress_callback(pct, f'Probing {done}/{len(hosts)} hosts…')

    return live


# ─── Port Scanner ─────────────────────────────────────────────────────────────

def _scan_ports(ip: str, ports: list = None) -> list:
    """TCP connect scan on common ports. Returns list of open port dicts."""
    if ports is None:
        ports = COMMON_PORTS

    open_ports = []
    lock = threading.Lock()

    def probe(port):
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(SCAN_TIMEOUT)
            result = s.connect_ex((ip, port))
            s.close()
            if result == 0:
                banner = _grab_banner(ip, port)
                with lock:
                    open_ports.append({
                        'port': port,
                        'service': PORT_SERVICES.get(port, 'Unknown'),
                        'banner': banner,
                        'state': 'open',
                    })
        except Exception:
            pass

    with ThreadPoolExecutor(max_workers=20) as ex:
        ex.map(probe, ports)

    return sorted(open_ports, key=lambda x: x['port'])


def _grab_banner(ip: str, port: int) -> str:
    """Try to grab service banner for fingerprinting"""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(1)
        s.connect((ip, port))
        if port in [80, 8080, 8443]:
            s.send(b'HEAD / HTTP/1.0\r\n\r\n')
        s.settimeout(0.5)
        banner = s.recv(256).decode('utf-8', errors='replace').strip()
        s.close()
        # Return just the first line
        return banner.split('\n')[0][:80]
    except Exception:
        return ''


# ─── Helpers ─────────────────────────────────────────────────────────────────

def _resolve_hostname(ip: str) -> str:
    try:
        return socket.gethostbyaddr(ip)[0]
    except Exception:
        return ip


def _mac_vendor(mac: str) -> str:
    """Rough vendor lookup from MAC OUI prefix"""
    oui_map = {
        'b8:27:eb': 'Raspberry Pi', 'dc:a6:32': 'Raspberry Pi',
        '00:50:56': 'VMware', '00:0c:29': 'VMware', '00:1a:11': 'Google',
        'ac:de:48': 'Apple', 'f4:5c:89': 'Apple', '3c:15:c2': 'Apple',
        '00:1b:21': 'Intel', '8c:8d:28': 'Intel',
        '00:e0:4c': 'Realtek', 'b4:2e:99': 'Cisco',
        'fc:fb:fb': 'Synology', '00:11:32': 'Synology',
    }
    prefix = mac[:8].lower()
    return oui_map.get(prefix, 'Unknown')


def _assess_risk(open_ports: list) -> str:
    """Rate risk level based on open ports"""
    high_risk = {21, 23, 135, 139, 445, 3389, 5900}    # FTP, Telnet, RDP, VNC, SMB
    medium_risk = {22, 3306, 5432, 6379, 27017}          # SSH, DBs
    ports = {p['port'] for p in open_ports}

    if ports & high_risk:
        return 'HIGH'
    if ports & medium_risk:
        return 'MEDIUM'
    if open_ports:
        return 'LOW'
    return 'NONE'


def quick_port_scan(ip: str, ports: list = None) -> dict:
    """Scan a single IP — used for on-demand scans from dashboard"""
    start = time.time()
    open_ports = _scan_ports(ip, ports or COMMON_PORTS)
    duration = round(time.time() - start, 2)
    return {
        'ip': ip,
        'hostname': _resolve_hostname(ip),
        'open_ports': open_ports,
        'risk': _assess_risk(open_ports),
        'scan_duration': duration,
        'scanned_at': datetime.utcnow().isoformat(),
    }