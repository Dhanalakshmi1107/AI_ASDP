import subprocess
from flask import Flask, request, jsonify
from flask_cors import CORS

app = Flask(__name__)
CORS(app)


def run_subfinder(target):
    try:
        result = subprocess.run(
            ["subfinder", "-d", target],
            capture_output=True,
            text=True
        )

        subdomains = result.stdout.splitlines()
        return subdomains

    except Exception as e:
        print("Subfinder error:", e)
        return []


@app.route("/start-scan", methods=["POST"])
def start_scan():
    data = request.json
    target = data.get("target")

    subdomains = run_subfinder(target)
    findings = run_nmap(target)
    technologies = run_whatweb(target)

    cves, insights = generate_cve_and_insights(technologies, findings)

    result = {
        "target": target,
        "subdomains": subdomains,
        "open_ports": findings,
        "technologies": technologies,
        "cves": cves,
        "findings": findings,
        "ai_insights": insights
    }

    return jsonify(result)

def run_nmap(target):
    try:
        result = subprocess.run(
            ["nmap", "-sV", target],
            capture_output=True,
            text=True
        )

        findings = []

        for line in result.stdout.splitlines():
            if "open" in line:
                parts = line.split()

                if len(parts) >= 3 and "/tcp" in parts[0]:
                    port = parts[0].split("/")[0]
                    service = parts[2]

                    findings.append({
                        "host": target,
                        "port": port,
                        "service": service,
                        "risk": "MED"
                    })

        return findings

    except Exception as e:
        print("Nmap error:", e)
        return []

def run_whatweb(target):
    try:
        result = subprocess.run(
            ["whatweb", target],
            capture_output=True,
            text=True
        )

        output = result.stdout

        technologies = []

        # simple parsing (can improve later)
        if "Apache" in output:
            technologies.append("Apache")
        if "nginx" in output:
            technologies.append("Nginx")
        if "PHP" in output:
            technologies.append("PHP")
        if "WordPress" in output:
            technologies.append("WordPress")

        return list(set(technologies))

    except Exception as e:
        print("WhatWeb error:", e)
        return []
    
def generate_cve_and_insights(technologies, findings):
    cves = []
    insights = []

    for tech in technologies:
        if "Apache" in tech:
            cves.append("CVE-2021-41773 (Apache Path Traversal)")
            insights.append("Apache server may be vulnerable to path traversal attacks")

        if "Nginx" in tech or "nginx" in tech:
            cves.append("CVE-2021-23017 (Nginx Memory Corruption)")
            insights.append("Nginx version may have known vulnerabilities")

        if "PHP" in tech:
            cves.append("CVE-2019-11043 (PHP-FPM RCE)")
            insights.append("PHP applications may be vulnerable to remote code execution")

    for f in findings:
        port = f["port"]

        if port == "22":
            insights.append("SSH port exposed — risk of brute force attacks")

        if port == "80":
            insights.append("HTTP service exposed — ensure secure configuration")

        if port == "443":
            insights.append("HTTPS detected — check TLS configuration")

    return list(set(cves)), list(set(insights))

if __name__ == "__main__":
    app.run(debug=True)