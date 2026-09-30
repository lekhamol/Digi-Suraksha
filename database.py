import sqlite3
import json
import datetime
import os

DB_PATH = os.path.join(os.path.dirname(__file__), 'digi_suraksha.db')

def get_connection():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    conn = get_connection()
    cursor = conn.cursor()

    # Table for scan history & detected threats
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS scan_logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            scan_type TEXT NOT NULL,           -- 'URL', 'MESSAGE', 'PASSWORD', 'WEBSITE'
            target_input TEXT NOT NULL,
            risk_score INTEGER NOT NULL,
            risk_level TEXT NOT NULL,          -- 'LOW', 'MEDIUM', 'HIGH', 'CRITICAL'
            details_json TEXT NOT NULL,
            timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
        )
    ''')

    # Table for alerts requiring user notification
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS security_alerts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            scan_id INTEGER,
            title TEXT NOT NULL,
            alert_type TEXT NOT NULL,
            severity TEXT NOT NULL,
            description TEXT NOT NULL,
            is_resolved INTEGER DEFAULT 0,
            timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (scan_id) REFERENCES scan_logs (id)
        )
    ''')

    # Table for user awareness progress / feedback
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS awareness_tips (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            category TEXT NOT NULL,
            title TEXT NOT NULL,
            summary TEXT NOT NULL,
            prevention_steps TEXT NOT NULL,
            icon TEXT DEFAULT 'shield-alert'
        )
    ''')

    # Insert initial sample logs if empty
    cursor.execute("SELECT COUNT(*) FROM scan_logs")
    if cursor.fetchone()[0] == 0:
        _seed_sample_data(cursor)

    conn.commit()
    conn.close()

def _seed_sample_data(cursor):
    sample_scans = [
        ("URL", "http://paypa1-security-login.xyz/verify", 90, "CRITICAL", {
            "indicators": ["Unencrypted Protocol (HTTP)", "High-Risk TLD (.xyz)", "Brand Impersonation (PayPal)"],
            "recommendation": "DANGER: Do NOT click this link."
        }),
        ("MESSAGE", "URGENT: SBI Account suspended. Update KYC at http://sbi-kyc-alert.online", 88, "CRITICAL", {
            "indicators": ["Security Panic Tactic", "High-Risk Embedded Link"],
            "recommendation": "ALERT: High probability of phishing or scam."
        }),
        ("URL", "https://github.com/login", 0, "LOW", {
            "indicators": ["No threat indicators found"],
            "recommendation": "SAFE: Legitimate domain."
        }),
        ("MESSAGE", "Hey, are we still meeting for dinner tonight at 8?", 0, "LOW", {
            "indicators": ["No suspicious patterns"],
            "recommendation": "SAFE: Standard communication."
        }),
        ("PASSWORD", "Password123!", 40, "MODERATE", {
            "indicators": ["Predictable word pattern"],
            "recommendation": "Consider making it longer with unique symbols."
        })
    ]

    for scan_type, target, score, level, details in sample_scans:
        cursor.execute(
            "INSERT INTO scan_logs (scan_type, target_input, risk_score, risk_level, details_json, timestamp) VALUES (?, ?, ?, ?, ?, ?)",
            (scan_type, target, score, level, json.dumps(details), datetime.datetime.now().isoformat())
        )
        scan_id = cursor.lastrowid

        if level in ["HIGH", "CRITICAL"]:
            cursor.execute(
                "INSERT INTO security_alerts (scan_id, title, alert_type, severity, description) VALUES (?, ?, ?, ?, ?)",
                (scan_id, f"High Risk {scan_type} Threat Detected", scan_type, level, f"Analyzed '{target[:40]}...' scored {score}% risk score.")
            )

    # Seed tips
    tips = [
        ("Phishing", "Recognizing Fake Links", "Phishing links often use typosquatting like 'g00gle.com' or unusual extensions like '.xyz'.", "Check the exact domain spelling in your browser address bar before entering passwords.", "link"),
        ("SMS Scams", "Urgent KYC & Banking Tricks", "Scammers use fake urgent SMS claiming your bank account or SIM card will be blocked.", "Banks will NEVER ask you to update KYC by clicking an unverified SMS link.", "message-square"),
        ("Passwords", "Credential Security Best Practices", "Using the same password across multiple websites puts all your accounts at risk.", "Use unique passwords for each service and enable 2-Factor Authentication (2FA).", "key"),
        ("Malware", "Drive-by Downloads & Malicious Sites", "Unsafe websites may trigger hidden automatic file downloads containing spyware or ransomware.", "Keep your browser updated and never grant unverified websites permission to download or run scripts.", "shield-check")
    ]
    for cat, title, summary, prev, icon in tips:
        cursor.execute(
            "INSERT INTO awareness_tips (category, title, summary, prevention_steps, icon) VALUES (?, ?, ?, ?, ?)",
            (cat, title, summary, prev, icon)
        )

def log_scan(scan_type, target_input, result):
    conn = get_connection()
    cursor = conn.cursor()

    risk_score = result.get('risk_score', result.get('strength_score', 0))
    risk_level = result.get('risk_level', result.get('status', 'LOW'))

    cursor.execute(
        "INSERT INTO scan_logs (scan_type, target_input, risk_score, risk_level, details_json) VALUES (?, ?, ?, ?, ?)",
        (scan_type, target_input, risk_score, risk_level, json.dumps(result))
    )
    scan_id = cursor.lastrowid

    if risk_level in ["HIGH", "CRITICAL"] or risk_score >= 70:
        cursor.execute(
            "INSERT INTO security_alerts (scan_id, title, alert_type, severity, description) VALUES (?, ?, ?, ?, ?)",
            (scan_id, f"High Threat {scan_type} Flagged", scan_type, risk_level, f"Target: '{target_input[:50]}'. Risk Score: {risk_score}%")
        )

    conn.commit()
    conn.close()
    return scan_id

def get_recent_scans(limit=20):
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM scan_logs ORDER BY timestamp DESC LIMIT ?", (limit,))
    rows = cursor.fetchall()
    conn.close()
    
    result = []
    for r in rows:
        item = dict(r)
        item['details'] = json.loads(item['details_json'])
        result.append(item)
    return result

def get_alerts():
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM security_alerts ORDER BY timestamp DESC")
    rows = cursor.fetchall()
    conn.close()
    return [dict(r) for r in rows]

def mark_alert_resolved(alert_id):
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("UPDATE security_alerts SET is_resolved = 1 WHERE id = ?", (alert_id,))
    conn.commit()
    conn.close()

def get_awareness_tips():
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM awareness_tips")
    rows = cursor.fetchall()
    conn.close()
    return [dict(r) for r in rows]

def get_stats():
    conn = get_connection()
    cursor = conn.cursor()

    cursor.execute("SELECT COUNT(*) FROM scan_logs")
    total_scans = cursor.fetchone()[0]

    cursor.execute("SELECT COUNT(*) FROM scan_logs WHERE risk_level IN ('HIGH', 'CRITICAL')")
    total_threats = cursor.fetchone()[0]

    cursor.execute("SELECT COUNT(*) FROM security_alerts WHERE is_resolved = 0")
    active_alerts = cursor.fetchone()[0]

    cursor.execute("SELECT scan_type, COUNT(*) as count FROM scan_logs GROUP BY scan_type")
    type_counts = dict(cursor.fetchall())

    cursor.execute("SELECT risk_level, COUNT(*) as count FROM scan_logs GROUP BY risk_level")
    level_counts = dict(cursor.fetchall())

    conn.close()
    return {
        "total_scans": total_scans,
        "total_threats": total_threats,
        "active_alerts": active_alerts,
        "scans_by_type": type_counts,
        "scans_by_level": level_counts
    }

if __name__ == "__main__":
    init_db()
    print("Database initialized successfully!")
    print("Stats:", get_stats())
