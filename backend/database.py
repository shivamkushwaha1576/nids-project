"""
Database models for the Network Intrusion Detection System
"""

from flask_sqlalchemy import SQLAlchemy
from datetime import datetime

db = SQLAlchemy()


class Alert(db.Model):
    __tablename__ = 'alerts'

    id = db.Column(db.Integer, primary_key=True)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow, index=True)
    src_ip = db.Column(db.String(45), nullable=False, index=True)
    dst_ip = db.Column(db.String(45))
    src_port = db.Column(db.Integer)
    dst_port = db.Column(db.Integer)
    protocol = db.Column(db.String(10))
    threat_type = db.Column(db.String(50), nullable=False)
    severity = db.Column(db.String(10), nullable=False)   # LOW | MEDIUM | HIGH | CRITICAL
    description = db.Column(db.Text)
    resolved = db.Column(db.Boolean, default=False)
    country = db.Column(db.String(50))
    city = db.Column(db.String(50))
    latitude = db.Column(db.Float)
    longitude = db.Column(db.Float)
    ai_anomaly_score = db.Column(db.Float)   # From Isolation Forest

    def to_dict(self):
        return {
            'id': self.id,
            'timestamp': self.timestamp.isoformat(),
            'src_ip': self.src_ip,
            'dst_ip': self.dst_ip,
            'src_port': self.src_port,
            'dst_port': self.dst_port,
            'protocol': self.protocol,
            'threat_type': self.threat_type,
            'severity': self.severity,
            'description': self.description,
            'resolved': self.resolved,
            'country': self.country,
            'city': self.city,
            'latitude': self.latitude,
            'longitude': self.longitude,
            'ai_anomaly_score': self.ai_anomaly_score
        }


class PacketLog(db.Model):
    __tablename__ = 'packet_logs'

    id = db.Column(db.Integer, primary_key=True)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow, index=True)
    src_ip = db.Column(db.String(45), index=True)
    dst_ip = db.Column(db.String(45))
    src_port = db.Column(db.Integer)
    dst_port = db.Column(db.Integer)
    protocol = db.Column(db.String(10))
    packet_size = db.Column(db.Integer)
    flags = db.Column(db.String(20))   # TCP flags (SYN, ACK, etc.)
    payload_snippet = db.Column(db.String(200))

    def to_dict(self):
        return {
            'id': self.id,
            'timestamp': self.timestamp.isoformat(),
            'src_ip': self.src_ip,
            'dst_ip': self.dst_ip,
            'src_port': self.src_port,
            'dst_port': self.dst_port,
            'protocol': self.protocol,
            'packet_size': self.packet_size,
            'flags': self.flags,
            'payload_snippet': self.payload_snippet
        }


class BlacklistedIP(db.Model):
    __tablename__ = 'blacklisted_ips'

    id = db.Column(db.Integer, primary_key=True)
    ip_address = db.Column(db.String(45), unique=True, nullable=False, index=True)
    reason = db.Column(db.String(200))
    blocked_at = db.Column(db.DateTime, default=datetime.utcnow)
    auto_blocked = db.Column(db.Boolean, default=False)

    def to_dict(self):
        return {
            'id': self.id,
            'ip_address': self.ip_address,
            'reason': self.reason,
            'blocked_at': self.blocked_at.isoformat(),
            'auto_blocked': self.auto_blocked
        }


class ThreatIntelligence(db.Model):
    """Known malicious IP database"""
    __tablename__ = 'threat_intelligence'

    id = db.Column(db.Integer, primary_key=True)
    ip_address = db.Column(db.String(45), unique=True, nullable=False, index=True)
    threat_type = db.Column(db.String(50))
    source = db.Column(db.String(100))    # e.g. "AbuseIPDB", "Manual"
    severity = db.Column(db.String(10))
    added_at = db.Column(db.DateTime, default=datetime.utcnow)
    last_seen = db.Column(db.DateTime)

    def to_dict(self):
        return {
            'id': self.id,
            'ip_address': self.ip_address,
            'threat_type': self.threat_type,
            'source': self.source,
            'severity': self.severity,
            'added_at': self.added_at.isoformat(),
        }


class User(db.Model):
    """User accounts for role-based access"""
    __tablename__ = 'users'

    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(50), unique=True, nullable=False, index=True)
    password_hash = db.Column(db.String(200), nullable=False)
    role = db.Column(db.String(20), nullable=False, default='analyst')  # admin | analyst
    display_name = db.Column(db.String(100))
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    last_login = db.Column(db.DateTime)
    is_active = db.Column(db.Boolean, default=True)

    def to_dict(self):
        return {
            'id': self.id,
            'username': self.username,
            'role': self.role,
            'display_name': self.display_name,
            'last_login': self.last_login.isoformat() if self.last_login else None,
        }


class ScanResult(db.Model):
    """Network mapper scan results"""
    __tablename__ = 'scan_results'

    id = db.Column(db.Integer, primary_key=True)
    scanned_at = db.Column(db.DateTime, default=datetime.utcnow, index=True)
    subnet = db.Column(db.String(20))
    hosts_found = db.Column(db.Integer, default=0)
    scan_data = db.Column(db.Text)   # JSON blob of full results

    def to_dict(self):
        return {
            'id': self.id,
            'scanned_at': self.scanned_at.isoformat(),
            'subnet': self.subnet,
            'hosts_found': self.hosts_found,
        }


def init_db(app):
    """Initialize database tables"""
    with app.app_context():
        db.create_all()
        print("✅ Database tables created/verified")

        # Seed some known threat intel IPs for demo
        known_bad = [
            ('185.220.101.1', 'TOR Exit Node', 'ThreatIntel', 'MEDIUM'),
            ('198.51.100.42', 'Known Scanner', 'AbuseIPDB', 'HIGH'),
            ('203.0.113.99', 'Botnet C2', 'Manual', 'CRITICAL'),
        ]
        for ip, ttype, source, sev in known_bad:
            if not ThreatIntelligence.query.filter_by(ip_address=ip).first():
                entry = ThreatIntelligence(
                    ip_address=ip, threat_type=ttype, source=source, severity=sev
                )
                db.session.add(entry)
        db.session.commit()
        print("✅ Threat intelligence seeded")