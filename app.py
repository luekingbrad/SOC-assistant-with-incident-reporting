import json
import sys
import os
from datetime import datetime

def analyze_alert(file_path):
    with open(file_path, "r") as file:
        data = json.load(file)

    description = data["rule"]["description"]
    agent = data["agent"]["name"]

    # Classification logic
    if "multiple failed login" in description.lower():
        category = "Brute Force Attack"
        severity = "High"
        mitre = "T1110"

    elif "failed login" in description.lower():
        category = "Login Failure"
        severity = "Medium"
        mitre = "T1110"

    elif "port scan" in description.lower() or "nmap" in description.lower():
        category = "Reconnaissance"
        severity = "Medium"
        mitre = "T1595"

    elif "new user" in description.lower():
        category = "Account Creation"
        severity = "High"
        mitre = "T1136"

    elif "service stopped" in description.lower():
        category = "Defense Evasion / Disruption"
        severity = "High"
        mitre = "T1562"

    else:
        category = "Unknown"
        severity = "Low"
        mitre = "Unknown"

    return {
        "file": file_path,
        "agent": agent,
        "description": description,
        "category": category,
        "severity": severity,
        "mitre": mitre
    }


# MAIN
path = sys.argv[1]
results = []

if os.path.isdir(path):
    print("Scanning folder of alerts...\n")
    for file in os.listdir(path):
        if file.endswith(".json"):
            results.append(analyze_alert(os.path.join(path, file)))
else:
    results.append(analyze_alert(path))


# ----------------------------
# CREATE INCIDENT REPORT (ENHANCED)
# ----------------------------

os.makedirs("reports", exist_ok=True)

timestamp = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
report_file = f"reports/incident_report_{timestamp}.md"

# Risk scoring system
severity_score = {
    "Low": 1,
    "Medium": 5,
    "High": 10
}

total_risk = 0
mitre_counts = {}

for r in results:
    total_risk += severity_score.get(r["severity"], 0)

    mitre = r["mitre"]
    if mitre in mitre_counts:
        mitre_counts[mitre] += 1
    else:
        mitre_counts[mitre] = 1

top_mitre = sorted(mitre_counts.items(), key=lambda x: x[1], reverse=True)

# Executive summary logic
if total_risk >= 25:
    risk_level = "CRITICAL"
elif total_risk >= 15:
    risk_level = "HIGH"
elif total_risk >= 5:
    risk_level = "MEDIUM"
else:
    risk_level = "LOW"

with open(report_file, "w") as report:
    report.write("# SECURITY INCIDENT REPORT\n\n")
    report.write(f"Generated: {datetime.now()}\n\n")

    # EXEC SUMMARY
    report.write("## EXECUTIVE SUMMARY\n")
    report.write(f"- Total Alerts: {len(results)}\n")
    report.write(f"- Overall Risk Level: {risk_level}\n")
    report.write(f"- Risk Score: {total_risk}\n\n")

    # TOP TECHNIQUES
    report.write("## TOP MITRE ATT&CK TECHNIQUES\n")
    for mitre, count in top_mitre:
        report.write(f"- {mitre}: {count} occurrences\n")
    report.write("\n")

    # DETAILED ALERTS
    report.write("## DETAILED ALERTS\n\n")
    for r in results:
        report.write("### Alert\n")
        report.write(f"- File: {r['file']}\n")
        report.write(f"- Agent: {r['agent']}\n")
        report.write(f"- Description: {r['description']}\n")
        report.write(f"- Category: {r['category']}\n")
        report.write(f"- Severity: {r['severity']}\n")
        report.write(f"- MITRE ATT&CK: {r['mitre']}\n\n")

    # ANALYST CONCLUSION
    report.write("## ANALYST CONCLUSION\n")
    report.write(f"This incident shows a {risk_level} risk profile with {len(results)} detected events. ")
    report.write("Immediate review is recommended for high severity indicators.\n")

print(f"\nEnhanced report generated: {report_file}")
