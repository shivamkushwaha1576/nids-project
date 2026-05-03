"""
Packet Sniffer Module
Uses Scapy for real capture OR generates realistic demo traffic
Requires root/admin for real capture; demo mode works without privileges
"""

import time
import random
import threading
from datetime import datetime
from collections import deque


DEMO_IPS = [
    '192.168.1.105', '192.168.1.22', '10.0.0.45',
    '172.16.0.12', '8.8.8.8', '1.1.1.1',
    '185.220.101.1',
    '203.0.113.99',
]

DEMO_EXTERNAL_IPS = [
    '5.188.206.14',
    '45.227.255.206',
    '103.75.190.12',
    '41.190.3.145',
    '195.54.160.149',
    '91.108.4.1',
    '185.156.73.54',
    '36.37.48.1',
    '59.127.96.1',
    '202.55.86.1',
    '196.202.99.1',
    '122.176.1.1',
    '49.50.70.1',
    '80.82.77.33',
    '62.210.180.1',
]

DEMO_PORTS = [80, 443, 22, 53, 8080, 3306, 5432, 25, 110, 8443, 21, 23]
DEMO_PROTOCOLS = ['TCP', 'UDP', 'ICMP']


class PacketSniffer:
    def __init__(self, detector, socketio):
        self.detector = detector
        self.socketio = socketio
        self.running = False
        self.packets_captured = 0
        self.current_interface = None
        self._stop_event = threading.Event()

    def start(self, interface=None, demo_mode=False):
        self.running = True
        self._stop_event.clear()
        self.current_interface = interface or ('demo' if demo_mode else 'auto')
        print(f"🟢 Sniffer starting — demo={demo_mode}")

        try:
            if demo_mode:
                print("🎭 Demo mode loop starting")
                self._demo_loop()
            else:
                print(f"🔍 Real sniff on: {interface or 'auto'}")
                self._real_sniff(interface)
        except Exception as e:
            import traceback
            print(f"❌ Sniffer crashed: {e}")
            traceback.print_exc()
        finally:
            self.running = False
            print("🔴 Sniffer stopped")

    def stop(self):
        self.running = False
        self._stop_event.set()
        print("🛑 Sniffer stopped")

    # ─── Real Packet Capture ──────────────────────────────────────────────────

    def _real_sniff(self, interface):
        try:
            from scapy.all import sniff, IP, TCP, UDP, ICMP, Raw
        except ImportError:
            print("⚠️  Scapy not installed. Falling back to demo mode...")
            self._demo_loop()
            return

        def packet_callback(pkt):
            if self._stop_event.is_set():
                return True
            if IP not in pkt:
                return
            packet_data = self._extract_from_scapy(pkt)
            self._process_packet(packet_data)

        try:
            sniff(
                iface=interface,
                prn=packet_callback,
                store=False,
                stop_filter=lambda x: self._stop_event.is_set()
            )
        except PermissionError:
            print("❌ Permission denied. Switching to demo mode...")
            self._demo_loop()
        except Exception as e:
            print(f"❌ Sniff error: {e}")
            self._demo_loop()

    def _extract_from_scapy(self, pkt):
        from scapy.all import IP, TCP, UDP, ICMP, Raw

        ip_layer = pkt[IP]
        src_ip = ip_layer.src
        dst_ip = ip_layer.dst
        protocol = 'OTHER'
        src_port = dst_port = flags = None
        payload = b''

        if TCP in pkt:
            protocol = 'TCP'
            src_port = pkt[TCP].sport
            dst_port = pkt[TCP].dport
            flags = str(pkt[TCP].flags)
        elif UDP in pkt:
            protocol = 'UDP'
            src_port = pkt[UDP].sport
            dst_port = pkt[UDP].dport
        elif ICMP in pkt:
            protocol = 'ICMP'

        if Raw in pkt:
            payload = bytes(pkt[Raw])[:200]

        return {
            'src_ip': src_ip, 'dst_ip': dst_ip,
            'src_port': src_port, 'dst_port': dst_port,
            'protocol': protocol, 'size': len(pkt),
            'flags': flags or '', 'payload': payload,
        }

    # ─── Demo Mode ────────────────────────────────────────────────────────────

    def _demo_loop(self):
        print("🎭 Demo loop running...")
        all_ips = DEMO_IPS + DEMO_EXTERNAL_IPS
        loop_count = 0

        while not self._stop_event.is_set():
            try:
                burst_size = random.randint(1, 8)

                for _ in range(burst_size):
                    if self._stop_event.is_set():
                        break

                    src_ip = random.choice(all_ips)
                    dst_ip = random.choice(['192.168.1.1', '10.0.0.1'] + all_ips)
                    protocol = random.choices(DEMO_PROTOCOLS, weights=[60, 30, 10])[0]
                    dst_port = random.choice(DEMO_PORTS)
                    src_port = random.randint(1024, 65535)
                    flags = ''
                    payload = b''

                    if protocol == 'TCP':
                        flags = random.choice(['S', 'SA', 'A', 'FA', 'S'])
                        if dst_port == 80 and random.random() < 0.1:
                            payload = random.choice([
                                b'GET / HTTP/1.1', b'POST /login',
                                b"' OR '1'='1", b'password=admin'
                            ])

                    packet_data = {
                        'src_ip': src_ip, 'dst_ip': dst_ip,
                        'src_port': src_port, 'dst_port': dst_port,
                        'protocol': protocol, 'size': random.randint(64, 1500),
                        'flags': flags, 'payload': payload,
                    }
                    self._process_packet(packet_data)

                loop_count += 1
                if loop_count % 20 == 0:
                    print(f"📦 Demo loop — {self.packets_captured} packets sent")

                time.sleep(random.uniform(0.1, 0.5))

            except Exception as e:
                import traceback
                print(f"❌ Demo loop error: {e}")
                traceback.print_exc()
                time.sleep(1)

    # ─── Shared Processing ────────────────────────────────────────────────────

    def _process_packet(self, packet_data):
        from app import app
        self.packets_captured += 1

        try:
            # Emit live packet to dashboard
            self.socketio.emit('packet', {
                'src_ip': packet_data['src_ip'],
                'dst_ip': packet_data['dst_ip'],
                'src_port': packet_data.get('src_port'),
                'dst_port': packet_data.get('dst_port'),
                'protocol': packet_data.get('protocol'),
                'size': packet_data.get('size'),
                'timestamp': datetime.utcnow().isoformat()
            })

            # Store packet log every 10 packets
            if self.packets_captured % 10 == 0:
                with app.app_context():
                    from database import db, PacketLog
                    log = PacketLog(
                        src_ip=packet_data['src_ip'],
                        dst_ip=packet_data['dst_ip'],
                        src_port=packet_data.get('src_port'),
                        dst_port=packet_data.get('dst_port'),
                        protocol=packet_data.get('protocol'),
                        packet_size=packet_data.get('size'),
                        flags=packet_data.get('flags', ''),
                        payload_snippet=packet_data.get('payload', b'')[:100].decode('utf-8', errors='replace')
                    )
                    db.session.add(log)
                    db.session.commit()

            # Run threat detection
            with app.app_context():
                threats = self.detector.analyze_packet(packet_data, app.app_context)
                for threat in threats:
                    self._handle_threat(threat, app)

        except Exception as e:
            import traceback
            print(f"⚠️ Packet processing error: {e}")
            traceback.print_exc()

    def _handle_threat(self, threat, app):
        """Persist threat to DB, emit alert, auto-block if critical"""
        with app.app_context():
            from database import db, Alert, BlacklistedIP

            alert = Alert(
                src_ip=threat['src_ip'],
                dst_ip=threat.get('dst_ip'),
                src_port=threat.get('src_port'),
                dst_port=threat.get('dst_port'),
                protocol=threat.get('protocol'),
                threat_type=threat['threat_type'],
                severity=threat['severity'],
                description=threat['description'],
                ai_anomaly_score=threat.get('ai_anomaly_score')
            )
            db.session.add(alert)

            if threat['severity'] == 'CRITICAL' and threat['src_ip']:
                existing = BlacklistedIP.query.filter_by(ip_address=threat['src_ip']).first()
                if not existing:
                    block = BlacklistedIP(
                        ip_address=threat['src_ip'],
                        reason=f"Auto-blocked: {threat['threat_type']}",
                        auto_blocked=True
                    )
                    db.session.add(block)

            db.session.commit()

        self.socketio.emit('new_alert', threat)
        print(f"🚨 [{threat['severity']}] {threat['threat_type']} from {threat['src_ip']}: {threat['description'][:80]}")

    def _get_app(self):
        from app import app
        return app