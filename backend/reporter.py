"""
Report Exporter
Generates PDF threat reports and CSV exports from alert/scan data.
PDF uses reportlab. CSV uses Python's built-in csv module.
"""

import csv
import json
import io
from datetime import datetime, timedelta


# ─── CSV Export ───────────────────────────────────────────────────────────────

def export_alerts_csv(alerts: list) -> bytes:
    """Convert alert list to CSV bytes"""
    output = io.StringIO()
    fieldnames = [
        'id', 'timestamp', 'severity', 'threat_type', 'src_ip',
        'dst_ip', 'src_port', 'dst_port', 'protocol',
        'country', 'city', 'description', 'resolved'
    ]
    writer = csv.DictWriter(output, fieldnames=fieldnames, extrasaction='ignore')
    writer.writeheader()
    for a in alerts:
        writer.writerow(a)
    return output.getvalue().encode('utf-8')


def export_scan_csv(scan_results: list) -> bytes:
    """Convert network scan results to CSV"""
    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(['IP', 'Hostname', 'MAC', 'Vendor', 'Open Ports', 'Services', 'Risk'])
    for host in scan_results:
        ports = ', '.join(str(p['port']) for p in host.get('open_ports', []))
        services = ', '.join(p['service'] for p in host.get('open_ports', []))
        writer.writerow([
            host.get('ip', ''), host.get('hostname', ''),
            host.get('mac', ''), host.get('vendor', ''),
            ports, services, host.get('risk', '')
        ])
    return output.getvalue().encode('utf-8')


# ─── PDF Export ───────────────────────────────────────────────────────────────

def export_alerts_pdf(alerts: list, stats: dict) -> bytes:
    """
    Generate a professional threat report PDF.
    Requires: pip install reportlab
    Falls back to a plain-text report if reportlab is unavailable.
    """
    try:
        from reportlab.lib.pagesizes import A4
        from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
        from reportlab.lib.units import cm
        from reportlab.lib import colors
        from reportlab.platypus import (
            SimpleDocTemplate, Paragraph, Spacer, Table,
            TableStyle, HRFlowable
        )
        from reportlab.lib.enums import TA_CENTER, TA_LEFT

        buffer = io.BytesIO()
        doc = SimpleDocTemplate(
            buffer, pagesize=A4,
            topMargin=2*cm, bottomMargin=2*cm,
            leftMargin=2*cm, rightMargin=2*cm
        )

        styles = getSampleStyleSheet()
        elements = []

        # ── Color palette ──
        dark     = colors.HexColor('#0a1a2e')
        accent   = colors.HexColor('#00cc7a')
        red      = colors.HexColor('#ff3e3e')
        orange   = colors.HexColor('#ff8c00')
        yellow   = colors.HexColor('#ffd700')
        blue     = colors.HexColor('#00bfff')
        mid_gray = colors.HexColor('#2a4a3a')
        lt_gray  = colors.HexColor('#f0f8f4')

        SEV_COLORS = {
            'CRITICAL': red, 'HIGH': orange, 'MEDIUM': yellow, 'LOW': blue
        }

        # ── Custom styles ──
        title_style = ParagraphStyle('Title',
            fontSize=22, fontName='Helvetica-Bold',
            textColor=dark, spaceAfter=4, alignment=TA_CENTER)
        subtitle_style = ParagraphStyle('Sub',
            fontSize=10, fontName='Helvetica',
            textColor=colors.HexColor('#4a7a5a'), alignment=TA_CENTER)
        section_style = ParagraphStyle('Section',
            fontSize=13, fontName='Helvetica-Bold',
            textColor=dark, spaceBefore=16, spaceAfter=6)
        body_style = ParagraphStyle('Body',
            fontSize=9, fontName='Helvetica',
            textColor=dark, spaceAfter=4)

        now = datetime.utcnow().strftime('%Y-%m-%d %H:%M UTC')

        # ── Header ──
        elements.append(Paragraph('🛡 NIDS Threat Report', title_style))
        elements.append(Paragraph(f'Generated: {now}', subtitle_style))
        elements.append(HRFlowable(width='100%', thickness=2, color=accent, spaceAfter=16))

        # ── Summary stats table ──
        elements.append(Paragraph('Executive Summary', section_style))
        summary_data = [
            ['Metric', 'Value'],
            ['Total Alerts', str(stats.get('total_alerts', len(alerts)))],
            ['Active Threats', str(stats.get('active_threats', '—'))],
            ['Blocked IPs', str(stats.get('blacklisted_ips', '—'))],
            ['Report Period', stats.get('period', 'Last 24 hours')],
        ]
        sev_counts = {}
        for a in alerts:
            s = a.get('severity', 'LOW')
            sev_counts[s] = sev_counts.get(s, 0) + 1
        for sev in ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW']:
            summary_data.append([f'{sev} Alerts', str(sev_counts.get(sev, 0))])

        summary_table = Table(summary_data, colWidths=[8*cm, 8*cm])
        summary_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), dark),
            ('TEXTCOLOR',  (0, 0), (-1, 0), accent),
            ('FONTNAME',   (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('FONTSIZE',   (0, 0), (-1, -1), 9),
            ('ROWBACKGROUNDS', (0, 1), (-1, -1), [lt_gray, colors.white]),
            ('GRID', (0, 0), (-1, -1), 0.5, mid_gray),
            ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
            ('LEFTPADDING', (0, 0), (-1, -1), 8),
            ('TOPPADDING', (0, 0), (-1, -1), 5),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 5),
        ]))
        elements.append(summary_table)
        elements.append(Spacer(1, 16))

        # ── Alert details table ──
        elements.append(Paragraph('Alert Details', section_style))
        headers = ['Time', 'Severity', 'Type', 'Source IP', 'Location', 'Description']
        rows = [headers]

        for a in alerts[:100]:   # cap at 100 rows for PDF size
            ts = a.get('timestamp', '')[:16].replace('T', ' ')
            loc = f"{a.get('city', '') or ''} {a.get('country', '') or ''}".strip() or '—'
            desc = (a.get('description', '') or '')[:60]
            if len(a.get('description', '')) > 60:
                desc += '…'
            rows.append([ts, a.get('severity', ''), a.get('threat_type', '').replace('_', ' ').upper(),
                         a.get('src_ip', ''), loc, desc])

        col_widths = [3*cm, 2.2*cm, 3.5*cm, 3*cm, 3*cm, 0]
        # Last column fills remaining space
        page_w = A4[0] - 4*cm
        col_widths[-1] = page_w - sum(col_widths[:-1])

        alert_table = Table(rows, colWidths=col_widths, repeatRows=1)
        row_styles = [
            ('BACKGROUND', (0, 0), (-1, 0), dark),
            ('TEXTCOLOR',  (0, 0), (-1, 0), accent),
            ('FONTNAME',   (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('FONTSIZE',   (0, 0), (-1, -1), 7.5),
            ('GRID', (0, 0), (-1, -1), 0.3, mid_gray),
            ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
            ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
            ('LEFTPADDING', (0, 0), (-1, -1), 5),
            ('TOPPADDING', (0, 0), (-1, -1), 4),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 4),
        ]
        # Color severity cells
        for i, row in enumerate(rows[1:], start=1):
            sev = row[1]
            clr = SEV_COLORS.get(sev, blue)
            row_styles.append(('TEXTCOLOR', (1, i), (1, i), clr))
            row_styles.append(('FONTNAME', (1, i), (1, i), 'Helvetica-Bold'))
            if i % 2 == 0:
                row_styles.append(('BACKGROUND', (0, i), (-1, i), lt_gray))

        alert_table.setStyle(TableStyle(row_styles))
        elements.append(alert_table)

        # ── Footer ──
        elements.append(Spacer(1, 20))
        elements.append(HRFlowable(width='100%', thickness=1, color=mid_gray))
        elements.append(Paragraph(
            'NIDS — Network Intrusion Detection System | Confidential',
            subtitle_style
        ))

        doc.build(elements)
        return buffer.getvalue()

    except ImportError:
        # Fallback: plain text "report"
        return _text_report_fallback(alerts, stats)


def _text_report_fallback(alerts: list, stats: dict) -> bytes:
    """Plain text report if reportlab is not installed"""
    lines = [
        '=' * 60,
        'NIDS THREAT REPORT',
        f'Generated: {datetime.utcnow().strftime("%Y-%m-%d %H:%M UTC")}',
        '=' * 60,
        '',
        'SUMMARY',
        f'  Total Alerts : {stats.get("total_alerts", len(alerts))}',
        f'  Active Threats: {stats.get("active_threats", "—")}',
        f'  Blocked IPs  : {stats.get("blacklisted_ips", "—")}',
        '',
        'ALERTS',
        '-' * 60,
    ]
    for a in alerts[:50]:
        lines.append(
            f'[{a.get("severity","?")}] {a.get("timestamp","")[:16]} | '
            f'{a.get("threat_type","").upper()} | {a.get("src_ip","?")} | '
            f'{a.get("description","")[:60]}'
        )
    lines += ['', '--- End of Report ---']
    return '\n'.join(lines).encode('utf-8')