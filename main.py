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

def run_sslscan(target, manager):
    print("[*] Running SSLScan (fallback mode)...")

    cmd = ["sslscan", f"{target}:443"]

    result = subprocess.run(cmd, capture_output=True, text=True)

    output = result.stdout

    host = manager.get_or_create_host(target)

    supported = []
    weak = []

    if "TLSv1.0" in output:
        weak.append("TLSv1.0")
        supported.append("TLSv1.0")

    if "TLSv1.1" in output:
        supported.append("TLSv1.1")

    if "TLSv1.2" in output:
        supported.append("TLSv1.2")

    if "TLSv1.3" in output:
        supported.append("TLSv1.3")

    host["tls"] = {
        "supported_versions": list(set(supported)),
        "weak_protocols": weak
    }

def run_wafwoof(target, manager):
    print("[*] Running WafW00f...")

    cmd = ["wafw00f", target]

    result = subprocess.run(cmd, capture_output=True, text=True)

    host = manager.get_or_create_host(manager.data["hosts"][0]["hostname"])

    if "No WAF detected" in result.stdout:
        host["waf"] = {
            "detected": False
        }
    else:
        host["waf"] = {
            "detected": True,
            "name": result.stdout.strip()
        }

def run_wappalyzer(target, manager):
    print("[*] Running Wappalyzer...")

    try:
        from Wappalyzer import Wappalyzer, WebPage

        url = f"http://{target}/"
        wappalyzer = Wappalyzer.latest()
        webpage = WebPage.new_from_url(url)
        results = wappalyzer.analyze_with_versions(webpage)

        host = manager.get_or_create_host(target)

        tech_list = []

        for tech, versions in results.items():
            version = None

            if isinstance(versions, list) and versions:
                version = versions[0]

            tech_list.append({
                "name": tech,
                "version": version
            })

        host["web_stack"] = {
            "technologies": tech_list
        }

    except Exception as e:
        print("[!] Wappalyzer failed:", e)

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
