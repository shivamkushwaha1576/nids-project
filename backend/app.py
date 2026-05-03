"""
Network Intrusion Detection System - Flask Backend
Handles API routes, WebSocket streaming, and threat coordination
"""

from flask import Flask, jsonify, request, render_template, send_file, make_response
from flask_socketio import SocketIO, emit
from flask_cors import CORS
import threading
import time
import json
import io
from datetime import datetime, timedelta
import random
import bcrypt
import os

from database import db, Alert, PacketLog, BlacklistedIP, User, ScanResult, init_db
from detector import ThreatDetector
from sniffer import PacketSniffer
import geoip
import network_mapper
import reporter
from auth import (
    generate_token, decode_token, get_token_from_request,
    login_required, admin_required, analyst_or_admin, init_auth
)

BASE_DIR = os.path.dirname(os.path.abspath(__file__))

app = Flask(
    __name__,
    template_folder=os.path.join(BASE_DIR, 'templates'),
    static_folder=os.path.join(BASE_DIR, 'static')
)
app.config['SECRET_KEY'] = 'nids-secret-key-change-in-production'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///ids.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

CORS(app)
socketio = SocketIO(app, cors_allowed_origins="*", async_mode='threading')
db.init_app(app)

detector = ThreatDetector()
sniffer = PacketSniffer(detector, socketio)

# Active network scan state
_scan_state = {'running': False, 'progress': 0, 'message': '', 'results': []}


# ─── Core Routes ──────────────────────────────────────────────────────────────

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/login')
def login_page():
    return render_template('login.html')


@app.route('/api/stats')
def get_stats():
    with app.app_context():
        total_alerts = Alert.query.count()
        active_threats = Alert.query.filter_by(resolved=False).count()
        blacklisted = BlacklistedIP.query.count()
        packets_today = PacketLog.query.filter(
            PacketLog.timestamp >= datetime.utcnow() - timedelta(hours=24)
        ).count()
        return jsonify({
            'total_alerts': total_alerts,
            'active_threats': active_threats,
            'blacklisted_ips': blacklisted,
            'packets_today': packets_today,
            'sniffer_running': sniffer.running
        })


@app.route('/api/alerts')
def get_alerts():
    page = request.args.get('page', 1, type=int)
    per_page = request.args.get('per_page', 50, type=int)
    severity = request.args.get('severity', None)
    query = Alert.query
    if severity:
        query = query.filter_by(severity=severity)
    alerts = query.order_by(Alert.timestamp.desc()).paginate(
        page=page, per_page=per_page, error_out=False
    )
    return jsonify({
        'alerts': [a.to_dict() for a in alerts.items],
        'total': alerts.total,
        'pages': alerts.pages,
        'current_page': page
    })


@app.route('/api/alerts/<int:alert_id>/resolve', methods=['POST'])
def resolve_alert(alert_id):
    alert = Alert.query.get_or_404(alert_id)
    alert.resolved = True
    db.session.commit()
    return jsonify({'success': True, 'message': f'Alert {alert_id} resolved'})


@app.route('/api/blacklist', methods=['GET'])
def get_blacklist():
    ips = BlacklistedIP.query.order_by(BlacklistedIP.blocked_at.desc()).all()
    return jsonify({'blacklist': [ip.to_dict() for ip in ips]})


@app.route('/api/blacklist', methods=['POST'])
def add_to_blacklist():
    data = request.json
    ip = data.get('ip')
    reason = data.get('reason', 'Manual block')
    if not ip:
        return jsonify({'error': 'IP required'}), 400
    existing = BlacklistedIP.query.filter_by(ip_address=ip).first()
    if existing:
        return jsonify({'error': 'IP already blacklisted'}), 409
    entry = BlacklistedIP(ip_address=ip, reason=reason)
    db.session.add(entry)
    db.session.commit()
    socketio.emit('ip_blacklisted', {'ip': ip, 'reason': reason})
    return jsonify({'success': True, 'entry': entry.to_dict()})


@app.route('/api/blacklist/<int:entry_id>', methods=['DELETE'])
def remove_from_blacklist(entry_id):
    entry = BlacklistedIP.query.get_or_404(entry_id)
    db.session.delete(entry)
    db.session.commit()
    return jsonify({'success': True})


@app.route('/api/traffic/history')
def traffic_history():
    hours = request.args.get('hours', 1, type=int)
    since = datetime.utcnow() - timedelta(hours=hours)
    logs = PacketLog.query.filter(PacketLog.timestamp >= since).all()
    buckets = {}
    for log in logs:
        minute = log.timestamp.strftime('%H:%M')
        buckets[minute] = buckets.get(minute, 0) + 1
    return jsonify({'history': buckets})


@app.route('/api/top-ips')
def top_ips():
    from sqlalchemy import func
    results = db.session.query(
        PacketLog.src_ip,
        func.count(PacketLog.id).label('count')
    ).group_by(PacketLog.src_ip).order_by(func.count(PacketLog.id).desc()).limit(10).all()
    return jsonify({'top_ips': [{'ip': r[0], 'count': r[1]} for r in results]})


@app.route('/api/protocols')
def protocol_distribution():
    from sqlalchemy import func
    results = db.session.query(
        PacketLog.protocol,
        func.count(PacketLog.id).label('count')
    ).group_by(PacketLog.protocol).all()
    return jsonify({'protocols': [{'protocol': r[0], 'count': r[1]} for r in results]})


# ─── Geo-IP Routes ────────────────────────────────────────────────────────────

@app.route('/api/geo/ip/<ip_addr>')
def geo_lookup_single(ip_addr):
    result = geoip.lookup(ip_addr)
    if result:
        result['flag'] = geoip.get_flag_emoji(result.get('country_code', ''))
        return jsonify({'success': True, 'ip': ip_addr, 'geo': result})
    return jsonify({'success': False, 'ip': ip_addr, 'geo': None})


@app.route('/api/geo/threat-map')
def geo_threat_map():
    hours = request.args.get('hours', 24, type=int)
    since = datetime.utcnow() - timedelta(hours=hours)
    alerts = Alert.query.filter(
        Alert.timestamp >= since,
        Alert.resolved == False
    ).order_by(Alert.timestamp.desc()).limit(200).all()

    seen = {}
    for a in alerts:
        ip = a.src_ip
        if not ip or geoip.is_private_ip(ip):
            continue
        if ip not in seen:
            seen[ip] = {
                'ip': ip, 'count': 0, 'severity': a.severity,
                'threat_types': set(), 'last_seen': a.timestamp.isoformat(),
                'lat': a.latitude, 'lng': a.longitude,
                'country': a.country, 'city': a.city,
                'flag': '🌐', 'isp': '',
            }
        seen[ip]['count'] += 1
        seen[ip]['threat_types'].add(a.threat_type)
        sev_order = ['LOW', 'MEDIUM', 'HIGH', 'CRITICAL']
        if sev_order.index(a.severity) > sev_order.index(seen[ip]['severity']):
            seen[ip]['severity'] = a.severity

    markers = []
    for ip, data in seen.items():
        if not data['lat'] or not data['lng']:
            geo = geoip.lookup(ip)
            if geo:
                data['lat'] = geo.get('lat')
                data['lng'] = geo.get('lng')
                data['country'] = geo.get('country', '')
                data['city'] = geo.get('city', '')
                data['flag'] = geoip.get_flag_emoji(geo.get('country_code', ''))
                data['isp'] = geo.get('isp', '')
                try:
                    Alert.query.filter_by(src_ip=ip, latitude=None).update({
                        'latitude': geo['lat'], 'longitude': geo['lng'],
                        'country': geo['country'], 'city': geo['city'],
                    })
                    db.session.commit()
                except Exception:
                    db.session.rollback()
        else:
            geo = geoip.lookup(ip) or {}
            data['flag'] = geoip.get_flag_emoji(geo.get('country_code', ''))

        data['threat_types'] = list(data['threat_types'])
        if data['lat'] and data['lng']:
            markers.append(data)

    return jsonify({'markers': markers, 'total': len(markers)})


@app.route('/api/geo/stats')
def geo_stats():
    alerts = Alert.query.filter(
        Alert.resolved == False,
        Alert.country != None,
        Alert.country != ''
    ).all()
    country_counts = {}
    for a in alerts:
        if a.country:
            country_counts[a.country] = country_counts.get(a.country, 0) + 1
    sorted_countries = sorted(country_counts.items(), key=lambda x: x[1], reverse=True)
    return jsonify({
        'top_countries': [{'country': c, 'count': n} for c, n in sorted_countries[:10]]
    })


# ─── Sniffer Control ──────────────────────────────────────────────────────────

@app.route('/api/sniffer/start', methods=['POST'])
def start_sniffer():
    data = request.json or {}
    interface = data.get('interface', None)
    demo_mode = data.get('demo_mode', False)
    if sniffer.running:
        return jsonify({'error': 'Sniffer already running'}), 409
    thread = threading.Thread(target=sniffer.start, args=(interface, demo_mode), daemon=True)
    thread.start()
    return jsonify({'success': True, 'message': 'Packet sniffer started'})


@app.route('/api/sniffer/stop', methods=['POST'])
def stop_sniffer():
    sniffer.stop()
    return jsonify({'success': True, 'message': 'Packet sniffer stopped'})


@app.route('/api/sniffer/status')
def sniffer_status():
    return jsonify({
        'running': sniffer.running,
        'packets_captured': sniffer.packets_captured,
        'interface': sniffer.current_interface
    })


# ─── Attack Simulation ────────────────────────────────────────────────────────

@app.route('/api/simulate/port-scan', methods=['POST'])
def simulate_port_scan():
    data = request.json or {}
    target_ip = data.get('target', '192.168.1.1')
    source_ip = data.get('source', f'10.0.0.{random.randint(2, 254)}')
    detector.simulate_port_scan(source_ip, target_ip, socketio, app)
    return jsonify({'success': True, 'message': f'Port scan simulation: {source_ip} → {target_ip}'})


@app.route('/api/simulate/brute-force', methods=['POST'])
def simulate_brute_force():
    data = request.json or {}
    source_ip = data.get('source', f'185.{random.randint(1,254)}.{random.randint(1,254)}.{random.randint(1,254)}')
    detector.simulate_brute_force(source_ip, socketio, app)
    return jsonify({'success': True, 'message': f'Brute force simulation from {source_ip}'})


# ─── Auth Routes ──────────────────────────────────────────────────────────────

@app.route('/api/auth/login', methods=['POST'])
def login():
    data = request.json or {}
    username = data.get('username', '').strip()
    password = data.get('password', '')

    if not username or not password:
        return jsonify({'error': 'Username and password required'}), 400

    user = User.query.filter_by(username=username, is_active=True).first()
    if not user or not bcrypt.checkpw(password.encode(), user.password_hash.encode()):
        return jsonify({'error': 'Invalid credentials'}), 401

    user.last_login = datetime.utcnow()
    db.session.commit()

    token = generate_token(user)
    return jsonify({
        'token': token,
        'user': {
            'username': user.username,
            'role': user.role,
            'display_name': user.display_name,
        }
    })


@app.route('/api/auth/me')
@login_required
def get_me():
    return jsonify({'user': request.current_user})


@app.route('/api/auth/logout', methods=['POST'])
def logout():
    # JWT is stateless — client just discards the token
    return jsonify({'success': True, 'message': 'Logged out'})


@app.route('/api/auth/users')
@admin_required
def list_users():
    users = User.query.all()
    return jsonify({'users': [u.to_dict() for u in users]})


@app.route('/api/auth/users', methods=['POST'])
@admin_required
def create_user():
    data = request.json or {}
    username = data.get('username', '').strip()
    password = data.get('password', '')
    role = data.get('role', 'analyst')
    display_name = data.get('display_name', username)

    if not username or not password:
        return jsonify({'error': 'Username and password required'}), 400
    if role not in ('admin', 'analyst'):
        return jsonify({'error': 'Role must be admin or analyst'}), 400
    if User.query.filter_by(username=username).first():
        return jsonify({'error': 'Username already exists'}), 409

    hashed = bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode()
    user = User(username=username, password_hash=hashed, role=role, display_name=display_name)
    db.session.add(user)
    db.session.commit()
    return jsonify({'success': True, 'user': user.to_dict()})


# ─── Network Mapper Routes ────────────────────────────────────────────────────

@app.route('/api/scan/network', methods=['POST'])
@login_required
def start_network_scan():
    global _scan_state
    if _scan_state['running']:
        return jsonify({'error': 'Scan already in progress'}), 409

    data = request.json or {}
    subnet = data.get('subnet') or network_mapper.get_local_network()

    def run_scan():
        global _scan_state
        _scan_state = {'running': True, 'progress': 0, 'message': 'Starting…', 'results': []}

        def on_progress(pct, msg):
            _scan_state['progress'] = pct
            _scan_state['message'] = msg
            socketio.emit('scan_progress', {'percent': pct, 'message': msg})

        try:
            results = network_mapper.scan_network(subnet, on_progress)
            _scan_state['results'] = results
            _scan_state['running'] = False
            _scan_state['progress'] = 100

            # Save to DB
            with app.app_context():
                scan = ScanResult(
                    subnet=subnet,
                    hosts_found=len(results),
                    scan_data=json.dumps(results)
                )
                db.session.add(scan)
                db.session.commit()

            socketio.emit('scan_complete', {
                'hosts_found': len(results),
                'subnet': subnet,
                'results': results
            })
        except Exception as e:
            _scan_state['running'] = False
            _scan_state['message'] = f'Error: {e}'
            socketio.emit('scan_error', {'error': str(e)})

    thread = threading.Thread(target=run_scan, daemon=True)
    thread.start()
    return jsonify({'success': True, 'subnet': subnet, 'message': 'Scan started'})


@app.route('/api/scan/status')
@login_required
def scan_status():
    return jsonify({
        'running': _scan_state['running'],
        'progress': _scan_state['progress'],
        'message': _scan_state['message'],
        'hosts_found': len(_scan_state.get('results', [])),
    })


@app.route('/api/scan/results')
@login_required
def scan_results():
    return jsonify({'results': _scan_state.get('results', [])})


@app.route('/api/scan/host', methods=['POST'])
@login_required
def scan_single_host():
    data = request.json or {}
    ip = data.get('ip')
    if not ip:
        return jsonify({'error': 'IP required'}), 400
    result = network_mapper.quick_port_scan(ip)
    return jsonify({'success': True, 'result': result})


@app.route('/api/scan/history')
@login_required
def scan_history():
    scans = ScanResult.query.order_by(ScanResult.scanned_at.desc()).limit(10).all()
    return jsonify({'history': [s.to_dict() for s in scans]})


@app.route('/api/scan/local-network')
@login_required
def get_local_network():
    return jsonify({
        'subnet': network_mapper.get_local_network(),
        'local_ip': network_mapper.get_local_ip(),
    })


# ─── Report Export Routes ─────────────────────────────────────────────────────

@app.route('/api/reports/alerts.csv')
@login_required
def export_alerts_csv():
    hours = request.args.get('hours', 24, type=int)
    since = datetime.utcnow() - timedelta(hours=hours)
    severity = request.args.get('severity')

    query = Alert.query.filter(Alert.timestamp >= since)
    if severity:
        query = query.filter_by(severity=severity)
    alerts = query.order_by(Alert.timestamp.desc()).all()

    csv_bytes = reporter.export_alerts_csv([a.to_dict() for a in alerts])
    response = make_response(csv_bytes)
    response.headers['Content-Type'] = 'text/csv'
    response.headers['Content-Disposition'] = \
        f'attachment; filename=nids_alerts_{datetime.utcnow().strftime("%Y%m%d_%H%M")}.csv'
    return response


@app.route('/api/reports/alerts.pdf')
@login_required
def export_alerts_pdf():
    hours = request.args.get('hours', 24, type=int)
    since = datetime.utcnow() - timedelta(hours=hours)
    alerts = Alert.query.filter(
        Alert.timestamp >= since
    ).order_by(Alert.timestamp.desc()).limit(200).all()

    stats = {
        'total_alerts': Alert.query.count(),
        'active_threats': Alert.query.filter_by(resolved=False).count(),
        'blacklisted_ips': BlacklistedIP.query.count(),
        'period': f'Last {hours} hours',
    }

    pdf_bytes = reporter.export_alerts_pdf([a.to_dict() for a in alerts], stats)

    # Check if we got PDF or fallback text
    is_pdf = pdf_bytes[:4] == b'%PDF'
    content_type = 'application/pdf' if is_pdf else 'text/plain'
    ext = 'pdf' if is_pdf else 'txt'

    response = make_response(pdf_bytes)
    response.headers['Content-Type'] = content_type
    response.headers['Content-Disposition'] = \
        f'attachment; filename=nids_report_{datetime.utcnow().strftime("%Y%m%d_%H%M")}.{ext}'
    return response


@app.route('/api/reports/scan.csv')
@login_required
def export_scan_csv():
    results = _scan_state.get('results', [])
    if not results:
        # Try last DB scan
        last = ScanResult.query.order_by(ScanResult.scanned_at.desc()).first()
        if last and last.scan_data:
            results = json.loads(last.scan_data)

    if not results:
        return jsonify({'error': 'No scan data available. Run a network scan first.'}), 404

    csv_bytes = reporter.export_scan_csv(results)
    response = make_response(csv_bytes)
    response.headers['Content-Type'] = 'text/csv'
    response.headers['Content-Disposition'] = \
        f'attachment; filename=nids_scan_{datetime.utcnow().strftime("%Y%m%d_%H%M")}.csv'
    return response


# ─── WebSocket Events ─────────────────────────────────────────────────────────

@socketio.on('connect')
def on_connect():
    print(f'Client connected: {request.sid}')
    emit('connected', {'message': 'Connected to NIDS WebSocket', 'timestamp': datetime.utcnow().isoformat()})


@socketio.on('disconnect')
def on_disconnect():
    print(f'Client disconnected: {request.sid}')


@socketio.on('request_stats')
def on_request_stats():
    with app.app_context():
        stats_response = get_stats()
        emit('stats_update', json.loads(stats_response.data))


# ─── App Startup ──────────────────────────────────────────────────────────────

if __name__ == '__main__':
    with app.app_context():
        init_db(app)
        init_auth(app, db)
    print("🛡️  NIDS Backend starting on http://localhost:5000")
    print("👤  Default users: admin/admin123 | analyst/analyst123")
    socketio.run(app, host='0.0.0.0', port=5000, debug=True, allow_unsafe_werkzeug=True)