from flask import Flask, request, jsonify, send_from_directory, Response
from flask_cors import CORS
import os
import json
import datetime

from threat_engine import ThreatEngine
import database as db

app = Flask(__name__, static_folder='static', static_url_path='')
CORS(app)

# Initialize Threat Engine & Database
engine = ThreatEngine()
db.init_db()

@app.route('/')
def index():
    return send_from_directory(app.static_folder, 'index.html')

@app.route('/api/scan/url', methods=['POST'])
def scan_url():
    data = request.json or {}
    url = data.get('url', '').strip()
    if not url:
        return jsonify({"error": "Please provide a valid URL"}), 400

    result = engine.analyze_url(url)
    scan_id = db.log_scan('URL', url, result)
    result['scan_id'] = scan_id
    result['timestamp'] = datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    return jsonify(result)

@app.route('/api/scan/message', methods=['POST'])
def scan_message():
    data = request.json or {}
    message = data.get('message', '').strip()
    if not message:
        return jsonify({"error": "Please provide message text to analyze"}), 400

    result = engine.analyze_message(message)
    scan_id = db.log_scan('MESSAGE', message[:100], result)
    result['scan_id'] = scan_id
    result['timestamp'] = datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    return jsonify(result)

@app.route('/api/scan/password', methods=['POST'])
def scan_password():
    data = request.json or {}
    password = data.get('password', '')
    if not password:
        return jsonify({"error": "Please enter a password"}), 400

    result = engine.analyze_password(password)
    # Mask password for privacy when logging
    masked_target = password[0] + "*" * (len(password) - 2) + password[-1] if len(password) > 2 else "***"
    scan_id = db.log_scan('PASSWORD', masked_target, result)
    result['scan_id'] = scan_id
    result['timestamp'] = datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    return jsonify(result)

@app.route('/api/history', methods=['GET'])
def get_history():
    limit = request.args.get('limit', 30, type=int)
    history = db.get_recent_scans(limit)
    return jsonify(history)

@app.route('/api/alerts', methods=['GET'])
def get_alerts():
    alerts = db.get_alerts()
    return jsonify(alerts)

@app.route('/api/alerts/<int:alert_id>/resolve', methods=['POST'])
def resolve_alert(alert_id):
    db.mark_alert_resolved(alert_id)
    return jsonify({"success": True, "message": f"Alert #{alert_id} marked as resolved"})

@app.route('/api/stats', methods=['GET'])
def get_stats():
    stats = db.get_stats()
    return jsonify(stats)

@app.route('/api/tips', methods=['GET'])
def get_tips():
    tips = db.get_awareness_tips()
    return jsonify(tips)

@app.route('/api/export/report', methods=['GET'])
def export_report():
    stats = db.get_stats()
    history = db.get_recent_scans(50)
    alerts = db.get_alerts()

    report_data = {
        "system": "Digi Suraksha Threat Intelligence System",
        "generated_at": datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
        "summary": stats,
        "active_alerts": alerts,
        "recent_scan_audit": history
    }

    response_json = json.dumps(report_data, indent=2)
    return Response(
        response_json,
        mimetype="application/json",
        headers={"Content-disposition": "attachment; filename=digi_suraksha_security_report.json"}
    )

if __name__ == '__main__':
    port = int(os.environ.get('PORT', 5000))
    print(f"Digi Suraksha Backend Server running on http://127.0.0.1:{port}")
    app.run(host='0.0.0.0', port=port, debug=True)
