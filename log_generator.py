#!/usr/bin/env python3
"""
SIEM Real-Time Log Generator - ADVANCED VERSION
Generates realistic security events with ML anomalies and insider threats
"""

import json
import random
import time
import os
from datetime import datetime
from threading import Thread

# Configuration
LOG_FILE_JSON = "D:/siem-dashboard/logs/sample-logs.log"
LOG_FILE_APACHE = "D:/siem-dashboard/logs/apache-logs.log"
GENERATION_INTERVAL = 2  # seconds between events

# Enhanced threat configurations with more attack types
THREAT_TYPES = {
    # Network-based attacks
    "brute_force": {
        "level": "ERROR",
        "source": "auth",
        "event": "login_failed",
        "messages": [
            "Failed login attempt for user {user} from IP {ip}",
            "Authentication failure for account {user} from {ip}",
            "Invalid credentials supplied by {user} at {ip}",
            "Multiple failed attempts detected for {user} from {ip}"
        ],
        "users": ["admin", "root", "administrator", "user", "guest", "test", "oracle", "postgres", "mysql", "sa"]
    },
    
    "sql_injection": {
        "level": "CRITICAL",
        "source": "waf",
        "event": "sql_injection",
        "messages": [
            "SQL injection attempt detected in query parameter: {payload}",
            "Suspicious SQL pattern blocked from {ip}: {payload}",
            "Potential database attack from {ip} with payload: {payload}",
            "UNION-based injection attempt from {ip}"
        ],
        "payloads": [
            "' OR '1'='1",
            "'; DROP TABLE users; --",
            "UNION SELECT * FROM passwords",
            "' OR 1=1 --",
            "1' AND 1=1 --",
            "' OR 'a'='a",
            "1; EXEC xp_cmdshell('net user')",
            "' UNION SELECT username,password FROM admin--"
        ]
    },
    
    "xss_attempt": {
        "level": "CRITICAL",
        "source": "waf",
        "event": "xss_attempt",
        "messages": [
            "Cross-site scripting attempt blocked from {ip}",
            "XSS payload detected in request from {ip}: {payload}",
            "Script injection attempt from {ip}",
            "Reflected XSS attempt from {ip}"
        ],
        "payloads": [
            "<script>alert('xss')</script>",
            "<img src=x onerror=alert('xss')>",
            "javascript:alert('xss')",
            "<svg onload=alert('xss')>",
            "'-alert(1)-'",
            "<body onload=alert('xss')>"
        ]
    },
    
    # Malware and file-based threats
    "malware_detected": {
        "level": "ERROR",
        "source": "antivirus",
        "event": "malware_detected",
        "messages": [
            "Malware signature detected in upload from {ip}: {file}",
            "Trojan file uploaded by {user} from {ip}: {file}",
            "Virus detected in file from {ip}: {file}",
            "Ransomware pattern detected in {file} from {ip}"
        ],
        "files": ["invoice.exe", "document.pdf.exe", "update.zip", "patch.bat", "setup.exe", 
                  "payment.exe", "report.doc.exe", "shipping_label.exe", "receipt.pdf.scr"],
        "users": ["john.doe", "jane.smith", "contractor1", "temp.user", "vendor.support"]
    },
    
    "ransomware_detected": {
        "level": "CRITICAL",
        "source": "edr",
        "event": "ransomware_detected",
        "messages": [
            "Ransomware activity detected on endpoint {ip}: {file}",
            "File encryption behavior detected from {ip}",
            "Suspicious file modifications detected: {file}",
            "Known ransomware variant detected: {file}"
        ],
        "files": ["encrypted_files.exe", "decryptor.exe", "readme.txt", "YOUR_FILES_ENCRYPTED.html"],
        "extensions": [".locked", ".encrypted", ".crypto", ".ransom"]
    },
    
    # Privilege and access attacks
    "privilege_escalation": {
        "level": "CRITICAL",
        "source": "audit",
        "event": "privilege_escalation",
        "messages": [
            "Privilege escalation attempt detected from {ip}",
            "Unauthorized sudo command from user {user} at {ip}",
            "Suspicious root access attempt from {ip}",
            "Kernel exploit attempt detected from {ip}"
        ],
        "users": ["lowpriv_user", "guest", "temp_admin", "service_account", "backup_user"]
    },
    
    "credential_stuffing": {
        "level": "ERROR",
        "source": "auth",
        "event": "credential_stuffing",
        "messages": [
            "Credential stuffing attack detected from {ip}",
            "Multiple account login attempts from {ip}",
            "Automated login pattern detected from {ip}",
            "Known compromised credentials used from {ip}"
        ],
        "users": ["admin", "user", "test", "support", "helpdesk"]
    },
    
    # Network reconnaissance
    "port_scan": {
        "level": "WARN",
        "source": "ids",
        "event": "port_scan",
        "messages": [
            "Port scan detected from external IP {ip}",
            "Reconnaissance activity detected from {ip}",
            "Multiple port connection attempts from {ip}",
            "SYN flood detected from {ip}"
        ],
        "ports": ["22,80,443,3306,5432,3389", "3389,445,139,135,5985", 
                  "21,22,23,25,53,80,110,143,443", "6379,27017,9200,5601,5044"]
    },
    
    "network_reconnaissance": {
        "level": "WARN",
        "source": "network",
        "event": "network_recon",
        "messages": [
            "Network enumeration detected from {ip}",
            "ARP scanning detected from {ip}",
            "DNS enumeration from {ip}",
            "SMB share enumeration from {ip}"
        ]
    },
    
    # Data exfiltration
    "data_exfiltration": {
        "level": "CRITICAL",
        "source": "dlp",
        "event": "data_exfiltration",
        "messages": [
            "Data exfiltration attempt detected from {ip}",
            "Large data transfer to external destination from {ip}",
            "Sensitive file upload detected from {ip}",
            "Database dump detected from {ip}"
        ],
        "users": ["contractor1", "consultant", "external_vendor", "temp.employee"],
        "destinations": ["mega.nz", "dropbox.com", "drive.google.com", "pastebin.com"]
    },
    
    "insider_threat": {
        "level": "CRITICAL",
        "source": "ueba",
        "event": "insider_threat",
        "messages": [
            "Insider threat detected: User {user} accessed sensitive files from {ip}",
            "Unusual data access pattern for user {user}",
            "After-hours sensitive file access by {user}",
            "User {user} downloaded large amount of data from {ip}"
        ],
        "users": ["disgruntled.employee", "contractor1", "departing.user", "privileged.user"]
    },
    
    # C2 and malicious connections
    "malicious_connection": {
        "level": "WARN",
        "source": "firewall",
        "event": "malicious_connection",
        "messages": [
            "Suspicious outbound connection to known malicious IP {dstip} from {ip}",
            "Connection to C2 server detected from {ip}",
            "Botnet communication attempt from {ip}",
            "Tor exit node connection from {ip}"
        ],
        "dstips": ["198.51.100.99", "203.0.113.45", "192.0.2.100", "185.220.101.42",
                   "109.70.100.20", "185.220.101.0", "45.142.212.100"]
    },
    
    "command_and_control": {
        "level": "CRITICAL",
        "source": "ndr",
        "event": "c2_beacon",
        "messages": [
            "C2 beacon detected from {ip} to {dstip}",
            "Periodic communication pattern detected: {ip}",
            "DNS tunneling detected from {ip}",
            "HTTPS beacon to suspicious domain from {ip}"
        ],
        "domains": ["evil-c2.com", "update-service.net", "cdn-analytics.org", "security-check.xyz"]
    },
    
    # Web attacks
    "unauthorized_access": {
        "level": "ERROR",
        "source": "web",
        "event": "unauthorized_access",
        "messages": [
            "Unauthorized access attempt to {resource} from {ip}",
            "Access denied for {user} to {resource} from {ip}",
            "Forbidden resource access from {ip}",
            "Admin panel access attempt from {ip}"
        ],
        "resources": ["/admin/config", "/api/users", "/database/admin", "/logs/system",
                      "/wp-admin", "/phpmyadmin", "/.env", "/config.xml"]
    },
    
    "path_traversal": {
        "level": "CRITICAL",
        "source": "waf",
        "event": "path_traversal",
        "messages": [
            "Path traversal attack detected from {ip}: {payload}",
            "Directory traversal attempt from {ip}",
            "Local file inclusion detected: {payload}"
        ],
        "payloads": ["../../../etc/passwd", "..\\..\\windows\\system32\\config\\sam",
                     "....//....//etc/shadow", "%2e%2e%2f%2e%2e%2f%2e%2e%2fetc/passwd"]
    },
    
    # Normal activity (for contrast)
    "normal_login": {
        "level": "INFO",
        "source": "auth",
        "event": "login_success",
        "messages": [
            "Successful login for user {user} from {ip}",
            "User {user} authenticated from {ip}",
            "Session established for {user} from {ip}"
        ],
        "users": ["john.doe", "jane.smith", "admin", "security_admin", "mike.wilson", "sarah.jones"]
    },
    
    "normal_access": {
        "level": "INFO",
        "source": "web",
        "event": "page_access",
        "messages": [
            "User {user} accessed {resource} from {ip}",
            "Normal page view: {resource} from {ip}",
            "API request from {user} at {ip}"
        ],
        "resources": ["/dashboard", "/api/data", "/reports", "/profile", "/home"],
        "users": ["john.doe", "jane.smith", "mike.wilson", "sarah.jones"]
    }
}

# IP ranges
INTERNAL_IPS = [f"192.168.1.{i}" for i in range(2, 50)] + \
               [f"10.0.0.{i}" for i in range(1, 50)] + \
               [f"172.16.0.{i}" for i in range(1, 50)]

EXTERNAL_IPS = [f"203.0.113.{i}" for i in range(1, 255)] + \
               [f"198.51.100.{i}" for i in range(1, 255)] + \
               [f"185.220.101.{i}" for i in range(1, 255)] + \
               [f"45.142.212.{i}" for i in range(1, 255)] + \
               [f"109.70.100.{i}" for i in range(1, 50)]

# ML anomaly tracking
anomaly_history = {}

def generate_ip(internal=False, threat_type=None):
    """Generate IP with context-aware logic"""
    # Insider threats come from internal IPs
    if threat_type == "insider_threat":
        return random.choice(INTERNAL_IPS)
    # C2 beacons often from compromised internal machines
    if threat_type == "command_and_control":
        return random.choice(INTERNAL_IPS) if random.random() < 0.7 else random.choice(EXTERNAL_IPS)
    
    if internal or random.random() < 0.3:
        return random.choice(INTERNAL_IPS)
    return random.choice(EXTERNAL_IPS)

def generate_timestamp():
    """Generate ISO 8601 timestamp"""
    return datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ")

def generate_ml_anomaly(ip, threat_type):
    """Generate ML-detected anomaly"""
    # Calculate anomaly score based on history
    if ip not in anomaly_history:
        anomaly_history[ip] = {"count": 0, "threats": []}
    
    anomaly_history[ip]["count"] += 1
    anomaly_history[ip]["threats"].append(threat_type)
    
    # High anomaly score if multiple different threat types from same IP
    unique_threats = len(set(anomaly_history[ip]["threats"]))
    base_score = 0.85
    ml_score = min(base_score + (unique_threats * 0.03), 0.99)
    
    anomaly_types = ["time_based", "volume_based", "pattern_based", "behavioral"]
    if unique_threats > 2:
        anomaly_types.append("multi_vector")
    
    return {
        "timestamp": generate_timestamp(),
        "level": "CRITICAL",
        "source": "ml_engine",
        "message": f"ML anomaly detected: Unusual activity pattern from {ip}. Score: {ml_score}",
        "clientip": ip,
        "event": "ml_anomaly",
        "threat_type": "anomaly_detected",
        "ml_score": round(ml_score, 2),
        "anomaly_type": random.choice(anomaly_types),
        "ml_confidence": "high" if ml_score > 0.95 else "medium",
        "indicators": anomaly_history[ip]["threats"][-3:]  # Last 3 threat types
    }

def generate_json_log(threat_type, include_ml=False):
    """Generate enhanced JSON log entry"""
    config = THREAT_TYPES[threat_type]
    ip = generate_ip(internal=(threat_type in ["normal_login", "normal_access", "insider_threat"]), 
                    threat_type=threat_type)
    
    log_entry = {
        "timestamp": generate_timestamp(),
        "level": config["level"],
        "source": config["source"],
        "clientip": ip,
        "event": config["event"],
        "threat_type": threat_type,
        "severity_score": {"CRITICAL": 10, "ERROR": 7, "WARN": 5, "INFO": 2}.get(config["level"], 1)
    }
    
    # Build message with variables
    message_vars = {"ip": ip}
    
    if "users" in config:
        message_vars["user"] = random.choice(config["users"])
    if "payloads" in config:
        message_vars["payload"] = random.choice(config["payloads"])
    if "files" in config:
        message_vars["file"] = random.choice(config["files"])
    if "resources" in config:
        message_vars["resource"] = random.choice(config["resources"])
    if "ports" in config:
        message_vars["ports"] = random.choice(config["ports"])
        log_entry["ports_scanned"] = message_vars["ports"]
    if "dstips" in config:
        dstip = random.choice(config["dstips"])
        message_vars["dstip"] = dstip
        log_entry["dstip"] = dstip
    if "domains" in config:
        domain = random.choice(config["domains"])
        message_vars["domain"] = domain
        log_entry["domain"] = domain
    if "destinations" in config:
        log_entry["destination"] = random.choice(config["destinations"])
    
    message_template = random.choice(config["messages"])
    log_entry["message"] = message_template.format(**message_vars)
    
    # Add user field
    if "user" in message_vars:
        log_entry["user"] = message_vars["user"]
    
    # Add response code for web events
    if config["source"] == "web":
        log_entry["response"] = 403 if threat_type in ["unauthorized_access", "path_traversal"] else 200
    
    # Add ML anomaly if requested
    if include_ml and random.random() < 0.3:
        log_entry["ml_detected"] = True
        log_entry["ml_insight"] = "Pattern matches known APT group TTPs"
    
    return json.dumps(log_entry), ip

def generate_apache_log(threat_type):
    """Generate Apache combined log format"""
    ip = generate_ip(internal=(threat_type in ["normal_login", "normal_access"]))
    timestamp = datetime.utcnow().strftime("%d/%b/%Y:%H:%M:%S +0000")
    
    # Status codes based on threat
    status_map = {
        "login_failed": 401,
        "unauthorized_access": 403,
        "sql_injection": 403,
        "xss_attempt": 403,
        "path_traversal": 403,
        "normal_login": 200,
        "normal_access": 200
    }
    
    status = status_map.get(threat_type, random.choice([200, 404, 500]))
    
    if "login" in threat_type:
        request = "POST /login HTTP/1.1"
        user = random.choice(["-", "admin", "john.doe"]) if threat_type == "login_failed" else "john.doe"
    elif "access" in threat_type:
        request = random.choice(["GET /admin/config HTTP/1.1", "GET /api/users HTTP/1.1", "GET /dashboard HTTP/1.1"])
        user = random.choice(["-", "guest", "admin"])
    else:
        request = random.choice(["GET /search HTTP/1.1", "POST /api/data HTTP/1.1", "GET /home HTTP/1.1"])
        user = "-"
    
    size = random.randint(100, 10000)
    referrer = random.choice(["-", "https://example.com/login", "https://google.com"])
    user_agent = random.choice([
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64)",
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7)",
        "curl/7.68.0",
        "Python-requests/2.28.0"
    ])
    
    return f'{ip} - {user} [{timestamp}] "{request}" {status} {size} "{referrer}" "{user_agent}"'

def log_generator():
    """Main log generation loop with ML anomalies"""
    print("=" * 70)
    print("    SIEM REAL-TIME LOG GENERATOR - ADVANCED VERSION")
    print("=" * 70)
    print(f"JSON logs:    {LOG_FILE_JSON}")
    print(f"Apache logs:  {LOG_FILE_APACHE}")
    print(f"Interval:     {GENERATION_INTERVAL} seconds")
    print(f"Threat types: {len(THREAT_TYPES)} categories")
    print("Features:     ML anomalies, Insider threats, Ransomware, C2 detection")
    print("=" * 70)
    print("Press Ctrl+C to stop")
    print("=" * 70)
    
    os.makedirs(os.path.dirname(LOG_FILE_JSON), exist_ok=True)
    
    # Weighted threat selection (more realistic distribution)
    threat_weights = {
        "normal_login": 15,
        "normal_access": 10,
        "brute_force": 12,
        "sql_injection": 8,
        "xss_attempt": 8,
        "malware_detected": 6,
        "ransomware_detected": 4,
        "privilege_escalation": 5,
        "credential_stuffing": 7,
        "port_scan": 6,
        "network_reconnaissance": 4,
        "data_exfiltration": 5,
        "insider_threat": 3,
        "malicious_connection": 5,
        "command_and_control": 4,
        "unauthorized_access": 8,
        "path_traversal": 5
    }
    
    threat_list = list(threat_weights.keys())
    weights = list(threat_weights.values())
    
    generated_count = 0
    
    while True:
        try:
            # Select threat type
            threat_type = random.choices(threat_list, weights=weights)[0]
            
            # Generate ML anomaly occasionally for high-threat IPs
            include_ml = (threat_type in ["brute_force", "data_exfiltration", "command_and_control"])
            
            # Generate JSON log
            json_log, ip = generate_json_log(threat_type, include_ml)
            with open(LOG_FILE_JSON, "a") as f:
                f.write(json_log + "\n")
            
            # Generate ML anomaly log separately (5% chance)
            if random.random() < 0.05:
                ml_log = generate_ml_anomaly(ip, threat_type)
                with open(LOG_FILE_JSON, "a") as f:
                    f.write(json.dumps(ml_log) + "\n")
                print(f"  [ML] Anomaly detected for {ip}: Score {ml_log['ml_score']}")
            
            # Generate Apache log (40% chance)
            if random.random() < 0.4:
                apache_log = generate_apache_log(threat_type)
                with open(LOG_FILE_APACHE, "a") as f:
                    f.write(apache_log + "\n")
            
            generated_count += 1
            
            # Print status
            print(f"[{datetime.now().strftime('%H:%M:%S')}] #{generated_count:04d} | {threat_type:20s} | {ip:15s} | {THREAT_TYPES[threat_type]['level']}")
            
            time.sleep(GENERATION_INTERVAL)
            
        except KeyboardInterrupt:
            print("\n" + "=" * 70)
            print(f"    Log generator stopped. Total events: {generated_count}")
            print("=" * 70)
            break
        except Exception as e:
            print(f"[!] Error: {e}")
            time.sleep(1)

if __name__ == "__main__":
    log_generator()