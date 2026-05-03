"""
Threat Detection Engine
Rule-based detection + AI anomaly detection using Isolation Forest
"""

from collections import defaultdict, deque
from datetime import datetime, timedelta
import time
import threading
import numpy as np

# ─── Rule-Based Detection Config ─────────────────────────────────────────────

PORT_SCAN_THRESHOLD = 15        # ports per window
PORT_SCAN_WINDOW = 10           # seconds
BRUTE_FORCE_THRESHOLD = 10      # failed connections
BRUTE_FORCE_WINDOW = 30         # seconds
DDoS_PACKET_THRESHOLD = 200     # packets per window
DDoS_WINDOW = 5                 # seconds

SEVERITY_MAP = {
    'port_scan': 'HIGH',
    'brute_force': 'CRITICAL',
    'ddos': 'CRITICAL',
    'suspicious_payload': 'MEDIUM',
    'known_bad_ip': 'HIGH',
    'ai_anomaly': 'MEDIUM',
    'repeated_connection': 'LOW',
}

SUSPICIOUS_KEYWORDS = [
    b'password', b'passwd', b'exec(', b'/bin/sh', b'cmd.exe',
    b'SELECT ', b'UNION ', b"' OR '", b'DROP TABLE',
    b'wget ', b'curl ', b'nc -e', b'base64',
]

COMMON_PORTS = {22, 23, 25, 53, 80, 110, 143, 443, 3306, 5432, 6379, 8080, 8443}


class ThreatDetector:
    def __init__(self):
        # Tracking windows: {ip: deque of timestamps}
        self._port_hits = defaultdict(lambda: defaultdict(list))   # ip → {port: [timestamps]}
        self._connection_failures = defaultdict(deque)              # ip → deque of timestamps
        self._packet_counts = defaultdict(deque)                    # ip → deque of timestamps
        self._lock = threading.Lock()

        # AI model (lazy-loaded)
        self._model = None
        self._feature_buffer = []
        self._model_trained = False
        self._training_samples = 500

    # ─── Public Interface ──────────────────────────────────────────────────────

    def analyze_packet(self, packet_data: dict, app_context) -> list:
        """
        Analyze a packet and return list of threat dicts (empty if clean).
        packet_data keys: src_ip, dst_ip, src_port, dst_port, protocol, size, flags, payload
        """
        threats = []
        src_ip = packet_data.get('src_ip', '')
        dst_port = packet_data.get('dst_port', 0)
        payload = packet_data.get('payload', b'')
        flags = packet_data.get('flags', '')

        with self._lock:
            # 1. Port scan detection
            scan_threat = self._check_port_scan(src_ip, dst_port, packet_data)
            if scan_threat:
                threats.append(scan_threat)

            # 2. Brute force (SYN flood / repeated connection attempts)
            if 'S' in flags and 'A' not in flags:   # SYN without ACK
                bf_threat = self._check_brute_force(src_ip, dst_port, packet_data)
                if bf_threat:
                    threats.append(bf_threat)

            # 3. DDoS detection
            ddos_threat = self._check_ddos(src_ip, packet_data)
            if ddos_threat:
                threats.append(ddos_threat)

            # 4. Payload inspection (DPI)
            if payload:
                dpi_threat = self._check_payload(src_ip, payload, packet_data)
                if dpi_threat:
                    threats.append(dpi_threat)

        # 5. Known bad IPs (DB lookup - needs app context)
        with app_context():
            intel_threat = self._check_threat_intel(src_ip, packet_data)
            if intel_threat:
                threats.append(intel_threat)

        # 6. AI anomaly detection (feed features, flag anomalies)
        ai_threat = self._check_ai_anomaly(packet_data)
        if ai_threat:
            threats.append(ai_threat)

        return threats

    # ─── Rule-Based Checks ─────────────────────────────────────────────────────

    def _check_port_scan(self, src_ip, dst_port, packet_data):
        now = time.time()
        window = self._port_hits[src_ip]
        window[dst_port].append(now)

        # Prune old entries
        cutoff = now - PORT_SCAN_WINDOW
        for port in list(window.keys()):
            window[port] = [t for t in window[port] if t > cutoff]
            if not window[port]:
                del window[port]

        unique_ports_hit = len(window)
        if unique_ports_hit >= PORT_SCAN_THRESHOLD:
            return self._build_threat(
                threat_type='port_scan',
                description=f'Port scan detected: {unique_ports_hit} ports in {PORT_SCAN_WINDOW}s. Ports: {list(window.keys())[:10]}',
                packet_data=packet_data,
                extra={'ports_hit': unique_ports_hit}
            )
        return None

    def _check_brute_force(self, src_ip, dst_port, packet_data):
        now = time.time()
        cutoff = now - BRUTE_FORCE_WINDOW
        queue = self._connection_failures[src_ip]
        queue.append(now)
        while queue and queue[0] < cutoff:
            queue.popleft()

        if len(queue) >= BRUTE_FORCE_THRESHOLD:
            service = self._port_to_service(dst_port)
            return self._build_threat(
                threat_type='brute_force',
                description=f'Brute force on {service} (port {dst_port}): {len(queue)} attempts in {BRUTE_FORCE_WINDOW}s',
                packet_data=packet_data,
                extra={'attempts': len(queue), 'service': service}
            )
        return None

    def _check_ddos(self, src_ip, packet_data):
        now = time.time()
        cutoff = now - DDoS_WINDOW
        queue = self._packet_counts[src_ip]
        queue.append(now)
        while queue and queue[0] < cutoff:
            queue.popleft()

        if len(queue) >= DDoS_PACKET_THRESHOLD:
            return self._build_threat(
                threat_type='ddos',
                description=f'DDoS/flood detected from {src_ip}: {len(queue)} packets in {DDoS_WINDOW}s',
                packet_data=packet_data,
                extra={'packet_rate': len(queue)}
            )
        return None

    def _check_payload(self, src_ip, payload, packet_data):
        payload_lower = payload.lower() if isinstance(payload, bytes) else payload.encode().lower()
        matched = [kw.lower() for kw in SUSPICIOUS_KEYWORDS if kw.lower() in payload_lower]
        if matched:
            snippet = payload[:100].decode('utf-8', errors='replace')
            return self._build_threat(
                threat_type='suspicious_payload',
                description=f'Suspicious payload from {src_ip}: keywords {matched}. Snippet: {snippet}',
                packet_data=packet_data,
                extra={'keywords': [k.decode() for k in matched]}
            )
        return None

    def _check_threat_intel(self, src_ip, packet_data):
        try:
            from database import ThreatIntelligence
            known = ThreatIntelligence.query.filter_by(ip_address=src_ip).first()
            if known:
                return self._build_threat(
                    threat_type='known_bad_ip',
                    description=f'Traffic from known malicious IP {src_ip} ({known.threat_type}, source: {known.source})',
                    packet_data=packet_data,
                    severity_override=known.severity
                )
        except Exception:
            pass
        return None

    # ─── AI Anomaly Detection ──────────────────────────────────────────────────

    def _extract_features(self, packet_data):
        """Extract numeric features for ML model"""
        return [
            packet_data.get('size', 0),
            packet_data.get('dst_port', 0),
            packet_data.get('src_port', 0),
            1 if packet_data.get('protocol') == 'TCP' else 0,
            1 if packet_data.get('protocol') == 'UDP' else 0,
            len(packet_data.get('flags', '')),
            1 if packet_data.get('dst_port', 0) in COMMON_PORTS else 0,
        ]

    def _check_ai_anomaly(self, packet_data):
        features = self._extract_features(packet_data)
        self._feature_buffer.append(features)

        # Train once we have enough samples
        if not self._model_trained and len(self._feature_buffer) >= self._training_samples:
            self._train_model()

        if self._model_trained:
            try:
                score = self._model.score_samples([features])[0]
                # Isolation Forest: more negative = more anomalous
                if score < -0.6:
                    return self._build_threat(
                        threat_type='ai_anomaly',
                        description=f'AI anomaly detected (score: {score:.3f}): unusual traffic pattern',
                        packet_data=packet_data,
                        extra={'anomaly_score': round(score, 4)}
                    )
            except Exception:
                pass
        return None

    def _train_model(self):
        try:
            from sklearn.ensemble import IsolationForest
            X = np.array(self._feature_buffer)
            self._model = IsolationForest(contamination=0.05, random_state=42, n_estimators=100)
            self._model.fit(X)
            self._model_trained = True
            print(f"✅ AI model trained on {len(X)} samples")
        except ImportError:
            print("⚠️  sklearn not installed — AI detection disabled")
        except Exception as e:
            print(f"⚠️  AI model training failed: {e}")

    # ─── Simulation ────────────────────────────────────────────────────────────

    def simulate_port_scan(self, src_ip, dst_ip, socketio, app):
        """Inject a fake port scan into the detection engine"""
        import random
        from database import Alert, db

        ports = random.sample(range(1, 65535), 25)
        threats = []

        with app.app_context():
            for port in ports[:20]:
                pd = {
                    'src_ip': src_ip, 'dst_ip': dst_ip,
                    'src_port': random.randint(1024, 65535),
                    'dst_port': port, 'protocol': 'TCP',
                    'size': 64, 'flags': 'S', 'payload': b''
                }
                with self._lock:
                    t = self._check_port_scan(src_ip, port, pd)
                    if t and not any(x['threat_type'] == 'port_scan' and x['src_ip'] == src_ip for x in threats):
                        threats.append(t)

            for threat in threats:
                alert = Alert(**{k: v for k, v in threat.items() if hasattr(Alert, k)})
                db.session.add(alert)
            db.session.commit()

            for threat in threats:
                socketio.emit('new_alert', threat)

    def simulate_brute_force(self, src_ip, socketio, app):
        """Inject a fake brute force attack"""
        import random
        from database import Alert, db

        with app.app_context():
            for _ in range(15):
                pd = {
                    'src_ip': src_ip, 'dst_ip': '192.168.1.1',
                    'src_port': random.randint(1024, 65535),
                    'dst_port': 22, 'protocol': 'TCP',
                    'size': 72, 'flags': 'S', 'payload': b''
                }
                with self._lock:
                    self._connection_failures[src_ip].append(time.time())

            threat = self._build_threat(
                threat_type='brute_force',
                description=f'SSH brute force detected from {src_ip}: 15 attempts in 30s',
                packet_data={'src_ip': src_ip, 'dst_ip': '192.168.1.1', 'dst_port': 22, 'protocol': 'TCP'}
            )
            alert = Alert(**{k: v for k, v in threat.items() if hasattr(Alert, k)})
            db.session.add(alert)
            db.session.commit()
            socketio.emit('new_alert', threat)

    # ─── Helpers ──────────────────────────────────────────────────────────────

    def _build_threat(self, threat_type, description, packet_data, extra=None, severity_override=None):
        severity = severity_override or SEVERITY_MAP.get(threat_type, 'LOW')
        return {
            'threat_type': threat_type,
            'severity': severity,
            'description': description,
            'src_ip': packet_data.get('src_ip', ''),
            'dst_ip': packet_data.get('dst_ip', ''),
            'src_port': packet_data.get('src_port'),
            'dst_port': packet_data.get('dst_port'),
            'protocol': packet_data.get('protocol', ''),
            'timestamp': datetime.utcnow().isoformat(),
            'extra': extra or {},
            'ai_anomaly_score': extra.get('anomaly_score') if extra else None,
        }

    def _port_to_service(self, port):
        services = {
            22: 'SSH', 23: 'Telnet', 21: 'FTP', 25: 'SMTP',
            80: 'HTTP', 443: 'HTTPS', 3306: 'MySQL', 5432: 'PostgreSQL',
            6379: 'Redis', 3389: 'RDP', 5900: 'VNC', 8080: 'HTTP-Alt'
        }
        return services.get(port, f'Port-{port}')