from flask import Flask, jsonify
from flask_cors import CORS
import datetime
import random
import time
from threading import Thread, Lock
from typing import List

from threat_intel_model import ThreatIntelligence, ThreatIndicator, ThreatType, ThreatSeverity

app = Flask(__name__)
CORS(app)

# Global threat intelligence system
ti = ThreatIntelligence()
data_lock = Lock()

def generate_sample_threat():
    """Generate a realistic sample threat"""
    threat_types = list(ThreatType)
    severities = list(ThreatSeverity)
    
    descriptions = [
        "Suspicious login attempts detected",
        "Potential data exfiltration activity",
        "New malware variant identified",
        "DDoS attack signature detected",
        "Phishing campaign targeting users",
        "Ransomware activity detected",
        "Unauthorized access attempt",
        "SQL injection attempts",
        "Zero-day vulnerability exploit"
    ]
    
    indicators = [
        f"192.168.{random.randint(1,255)}.{random.randint(1,255)}",
        f"malicious-domain-{random.randint(1,999)}.com",
        f"hash-{random.randint(10000,99999)}"
    ]
    
    return ThreatIndicator(
        type=random.choice(threat_types),
        source="automated-detection",
        timestamp=datetime.datetime.now() - datetime.timedelta(
            hours=random.randint(0, 72)
        ),
        description=random.choice(descriptions),
        indicators=random.sample(indicators, k=2),
        severity=random.choice(severities),
        confidence=random.uniform(0.6, 0.95)
    )

def threat_generator():
    """Background thread to generate threats periodically"""
    while True:
        with data_lock:
            # Generate 1-3 new threats
            for _ in range(random.randint(1, 3)):
                new_threat = generate_sample_threat()
                ti.add_threat(new_threat)
                
            # Remove old threats (older than 72 hours)
            current_time = datetime.datetime.now()
            ti.threats = [
                threat for threat in ti.threats 
                if (current_time - threat.timestamp).total_seconds() < 72 * 3600
            ]
        
        # Wait for 5-15 seconds before generating new threats
        time.sleep(random.uniform(5, 15))

@app.route('/api/threats/summary', methods=['GET'])
def get_threat_summary():
    with data_lock:
        total_threats = len(ti.threats)
        critical_threats = len([t for t in ti.threats if t.severity == ThreatSeverity.CRITICAL])
        
        # Count active campaigns (threats in last 24 hours)
        now = datetime.datetime.now()
        active_campaigns = len([
            t for t in ti.threats 
            if (now - t.timestamp).total_seconds() < 24 * 3600
        ])
        
        return jsonify({
            'totalThreats': total_threats,
            'criticalThreats': critical_threats,
            'activeCampaigns': active_campaigns
        })

@app.route('/api/threats/by-type', methods=['GET'])
def get_threats_by_type():
    with data_lock:
        type_counts = {}
        for threat in ti.threats:
            if threat.type.value not in type_counts:
                type_counts[threat.type.value] = 0
            type_counts[threat.type.value] += 1
        
        return jsonify([
            {'name': threat_type, 'count': count}
            for threat_type, count in type_counts.items()
        ])

@app.route('/api/threats/severity', methods=['GET'])
def get_severity_distribution():
    with data_lock:
        severity_counts = {}
        for threat in ti.threats:
            if threat.severity.name not in severity_counts:
                severity_counts[threat.severity.name] = 0
            severity_counts[threat.severity.name] += 1
        
        return jsonify([
            {'name': severity, 'value': count}
            for severity, count in severity_counts.items()
        ])

@app.route('/api/threats/trend', methods=['GET'])
def get_threat_trend():
    with data_lock:
        # Group threats by hour for the last 24 hours
        hours = {}
        now = datetime.datetime.now()
        for i in range(24):
            hour_key = (now - datetime.timedelta(hours=i)).strftime('%H:00')
            hours[hour_key] = 0
        
        for threat in ti.threats:
            if (now - threat.timestamp).total_seconds() <= 24 * 3600:
                hour_key = threat.timestamp.strftime('%H:00')
                if hour_key in hours:
                    hours[hour_key] += 1
        
        return jsonify([
            {'name': hour, 'threats': count}
            for hour, count in sorted(hours.items())
        ])

@app.route('/api/threats/recent', methods=['GET'])
def get_recent_threats():
    with data_lock:
        recent = sorted(ti.threats, key=lambda x: x.timestamp, reverse=True)[:10]
        return jsonify([{
            'id': i,
            'type': threat.type.value,
            'severity': threat.severity.name,
            'timestamp': threat.timestamp.strftime('%Y-%m-%d %H:%M:%S'),
            'description': threat.description
        } for i, threat in enumerate(recent, 1)])

if __name__ == '__main__':
    # Start the threat generator thread
    generator_thread = Thread(target=threat_generator, daemon=True)
    generator_thread.start()
    
    # Initialize with some sample threats
    with data_lock:
        for _ in range(20):
            ti.add_threat(generate_sample_threat())
    
    app.run(debug=True, use_reloader=False)