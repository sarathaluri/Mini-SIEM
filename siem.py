import json
from collections import defaultdict

log_file = "logs.txt"

failed_logins = defaultdict(int)
successful_logins = set()
ip_timestamps = defaultdict(list)
alerts = []

print("=" * 60)
print("         MINI SIEM SYSTEM - ADVANCED SOC TOOL")
print("=" * 60)

try:
    with open(log_file, "r") as file:
        for line in file:
            parts = line.strip().split()

            if len(parts) < 5:
                continue

            timestamp = parts[0] + " " + parts[1]
            ip = parts[2]
            message = " ".join(parts[4:])

            # Store timestamps per IP
            ip_timestamps[ip].append(timestamp)

            if "Failed login" in message:
                failed_logins[ip] += 1

            if "Login successful" in message:
                successful_logins.add(ip)

    alert_id = 1

    for ip, count in failed_logins.items():

        first_seen = ip_timestamps[ip][0]
        last_seen = ip_timestamps[ip][-1]

        # CRITICAL: brute force
        if count >= 5:
            alerts.append({
                "alert_id": alert_id,
                "ip": ip,
                "severity": "CRITICAL",
                "first_seen": first_seen,
                "last_seen": last_seen,
                "attempts": count,
                "type": "Brute Force",
                "message": f"Brute force attack detected ({count} attempts)"
            })
            alert_id += 1

        # HIGH
        elif count >= 3:
            alerts.append({
                "alert_id": alert_id,
                "ip": ip,
                "severity": "HIGH",
                "first_seen": first_seen,
                "last_seen": last_seen,
                "attempts": count,
                "type": "Multiple Failures",
                "message": f"Multiple failed logins ({count})"
            })
            alert_id += 1

        # MEDIUM
        elif count == 2:
            alerts.append({
                "alert_id": alert_id,
                "ip": ip,
                "severity": "MEDIUM",
                "first_seen": first_seen,
                "last_seen": last_seen,
                "attempts": count,
                "type": "Suspicious Activity",
                "message": "Suspicious login activity"
            })
            alert_id += 1

        # 🔥 CORRELATION RULE
        if ip in successful_logins and count >= 3:
            alerts.append({
                "alert_id": alert_id,
                "ip": ip,
                "severity": "CRITICAL",
                "first_seen": first_seen,
                "last_seen": last_seen,
                "attempts": count,
                "type": "Account Compromise",
                "message": "Failed logins followed by success"
            })
            alert_id += 1

    # Sort alerts
    severity_order = {"CRITICAL": 3, "HIGH": 2, "MEDIUM": 1}
    alerts.sort(key=lambda x: severity_order[x["severity"]], reverse=True)

    # Display alerts
    print("\n--- SECURITY ALERT DASHBOARD ---")
    for alert in alerts:
        print(f"[{alert['alert_id']}] [{alert['severity']}] {alert['ip']} | {alert['type']}")
        print(f"    Attempts: {alert['attempts']} | First: {alert['first_seen']} | Last: {alert['last_seen']}")

    # Summary
    critical = sum(1 for a in alerts if a["severity"] == "CRITICAL")
    high = sum(1 for a in alerts if a["severity"] == "HIGH")
    medium = sum(1 for a in alerts if a["severity"] == "MEDIUM")

    print("\n--- SUMMARY ---")
    print(f"Total IPs analyzed: {len(ip_timestamps)}")
    print(f"Total alerts: {len(alerts)}")
    print(f"Critical: {critical} | High: {high} | Medium: {medium}")

    # Save structured JSON
    with open("alerts.json", "w") as f:
        json.dump(alerts, f, indent=4)

    print("\nAlerts saved to alerts.json")

except FileNotFoundError:
    print("Log file not found.")