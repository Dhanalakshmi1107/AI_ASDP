import re


ANSI_ESCAPE_REGEX = re.compile(r"\x1b\[[0-9;]*m")
DOMAIN_REGEX = re.compile(
    r"\b(?=.{1,253}\b)(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[A-Za-z]{2,63}\b"
)
NMAP_PORT_REGEX = re.compile(
    r"^(?P<port>\d{1,5})/(?P<protocol>[a-z]+)\s+"
    r"(?P<state>\S+)\s+(?P<service>\S+)"
    r"(?:\s+(?P<product>.+))?$",
    re.IGNORECASE,
)
HTTP_STATUS_REGEX = re.compile(r"HTTP/\d(?:\.\d)?\s+(?P<status>\d{3})")
HTTP_HEADER_REGEX = re.compile(r"^(?P<name>[A-Za-z0-9\-]+):\s*(?P<value>.+)$")
WHATWEB_TOKEN_REGEX = re.compile(r"(?P<name>[A-Za-z0-9._+\-/ ]+)\[(?P<value>[^\]]+)\]")
WHATWEB_PREFIX_REGEX = re.compile(r"^\S+\s+\[[^\]]+\]\s*")
WHATWEB_IGNORE_NAMES = {
    "country",
    "ip",
    "title",
    "email",
    "script",
    "uncommonheaders",
    "x-frame-options",
    "x-powered-by",
    "cookie",
    "set-cookie",
    "cookies",
    "httponly",
    "meta-generator",
    "html5",
    "httpserver",
    "server",
    # HTTP response header names that occasionally leak through from
    # WhatWeb's UncommonHeaders/Cookies bracket lists. These are not
    # technologies — they are response metadata.
    "access-control-allow-origin",
    "access-control-allow-credentials",
    "access-control-allow-methods",
    "strict-transport-security",
    "content-security-policy",
    "referrer-policy",
    "x-content-type-options",
    "x-xss-protection",
    "x-cache",
    "x-cache-key",
    "x-cache-hits",
    "x-cache-status",
    "x-served-by",
    "x-styx-req-id",
    "x-timer",
    "x-request-id",
    "via",
    "via-proxy",
    "link",
    "frame",
    "redirectlocation",
    "speculationrules",
    "open-graph-protocol",
    "text/javascript",
    "text/html",
    "text/css",
    "application/json",
}


def parse_subfinder_output(output, target):
    target = target.lower().strip(".")
    seen = set()
    results = []

    for match in DOMAIN_REGEX.findall(output or ""):
        candidate = match.lower().strip(".")
        if candidate == target or candidate.endswith(f".{target}"):
            if candidate not in seen:
                seen.add(candidate)
                results.append({"name": candidate, "ip": "", "status": "active"})

    return results


def parse_nmap_output(output, default_host):
    services = []
    current_service = None

    for raw_line in (output or "").splitlines():
        line = raw_line.strip()
        match = NMAP_PORT_REGEX.match(line)

        if match:
            product_field = (match.group("product") or "").strip()
            product, version = split_product_version(product_field)
            current_service = {
                "host": default_host,
                "port": int(match.group("port")),
                "protocol": match.group("protocol").lower(),
                "status": match.group("state").lower(),
                "service_name": match.group("service").lower(),
                "product": product,
                "version": version,
                "scripts": [],
                "cve_matches": [],
            }
            services.append(current_service)
            continue

        if current_service and raw_line.startswith("|"):
            script_line = raw_line.lstrip("|_ ").strip()
            if ":" in script_line:
                script_id, summary = script_line.split(":", 1)
                current_service["scripts"].append(
                    {"script_id": script_id.strip(), "summary": summary.strip()}
                )

    return services


def parse_http_output(raw_output):
    status_code = 0
    headers = []
    seen = set()

    for line in (raw_output or "").splitlines():
        status_match = HTTP_STATUS_REGEX.search(line)
        if status_match and not status_code:
            status_code = int(status_match.group("status"))
            continue

        header_match = HTTP_HEADER_REGEX.match(line.strip())
        if header_match:
            name = header_match.group("name").strip().lower()
            value = header_match.group("value").strip()
            key = (name, value)
            if key not in seen:
                seen.add(key)
                headers.append({"name": name, "value": value})

    return {"status_code": status_code, "headers": headers}


def parse_sslscan_output(output):
    supported = []
    weak_protocols = []
    weak_ciphers = []

    for version in ("TLSv1.0", "TLSv1.1", "TLSv1.2", "TLSv1.3"):
        if version in (output or ""):
            supported.append(version)

    if "TLSv1.0" in supported:
        weak_protocols.append("TLSv1.0")
    if "TLSv1.1" in supported:
        weak_protocols.append("TLSv1.1")

    for cipher in re.findall(r"(TLS_[A-Z0-9_]+)", output or ""):
        if "3DES" in cipher or "RC4" in cipher or "DES" in cipher:
            if cipher not in weak_ciphers:
                weak_ciphers.append(cipher)

    return {
        "supported_versions": supported,
        "weak_protocols": weak_protocols,
        "weak_ciphers": weak_ciphers,
        "certificate_expired": "certificate expired" in (output or "").lower(),
    }


def parse_waf_output(output):
    """Parse wafw00f output into a {detected, name} record.

    wafw00f's stdout is a mix of status lines (``[*] Checking ...``,
    ``[~] Number of requests: N``) and result lines (``[+] The site X is
    behind Cloudflare WAF`` or ``[-] No WAF detected``). Earlier versions
    of this parser grabbed the last non-empty line which, on hosts that
    weren't reachable over HTTPS (like scanme.nmap.org), left the "Checking"
    preamble as the WAF name. We now scan specifically for the ``[+]``
    detection line with the "behind" keyword, and otherwise report no WAF.
    """
    cleaned = ANSI_ESCAPE_REGEX.sub("", output or "").strip()
    if not cleaned:
        return {"detected": False, "name": ""}

    lines = [line.strip() for line in cleaned.splitlines() if line.strip()]

    # Explicit negative signals first.
    for line in lines:
        lowered = line.lower()
        if "no waf detected" in lowered or "does not seem to be behind" in lowered:
            return {"detected": False, "name": ""}

    # Positive detection line: wafw00f prints "[+] The site ... is behind <name> WAF"
    for line in lines:
        stripped = line.strip()
        lowered = stripped.lower()
        if stripped.startswith("[+]") and "behind" in lowered:
            # Take everything after the last "behind"
            tail = stripped.split("behind", 1)[-1].strip()
            # wafw00f formats: "Cloudflare (Cloudflare Inc.) WAF." — trim trailing noise
            name = re.sub(r"\s+WAF\.?\s*$", "", tail, flags=re.IGNORECASE).strip(" .")
            if name:
                return {"detected": True, "name": name}

    # No positive detection line found — treat as undetected rather than
    # echoing status text (e.g. "[*] Checking https://target") as the WAF name.
    return {"detected": False, "name": ""}


def parse_whatweb_output(output):
    output = ANSI_ESCAPE_REGEX.sub("", output or "")
    server = {"name": "", "version": ""}
    technologies = []
    seen = set()

    for raw_line in output.splitlines():
        line = WHATWEB_PREFIX_REGEX.sub("", raw_line.strip())
        if not line:
            continue

        for segment in _split_whatweb_line(line):
            name, value = _parse_whatweb_segment(segment)
            if not name:
                continue

            lowered = name.lower()
            if lowered in {"httpserver", "server"}:
                server_name, server_version = split_product_version(value)
                server["name"] = server_name
                server["version"] = server_version
                continue

            if not _is_useful_technology(name, value):
                continue

            # Canonicalise + suppress noisy version values for analytics tags
            # (WhatWeb emits Google-Analytics[UA-11009417-1] — the tracker ID
            # is not a software version and shouldn't appear as one).
            name, value, suppress_version = _canonicalise_tech_name(name, value)
            version = "" if suppress_version else extract_version(value)
            category = categorize_technology(name)
            item_key = (name, version, category)

            if item_key not in seen:
                seen.add(item_key)
                technologies.append({"name": name, "version": version, "category": category})

    return {"server": server, "technologies": technologies}


def extract_http_signal_techs(headers, html=""):
    """Extract technology fingerprints from HTTP response headers and HTML body.

    This is a lightweight, regex-based detector that complements WhatWeb and
    Wappalyzer. It captures signals those tools sometimes miss (JSESSIONID →
    Java, inline GTM snippets, meta-generator CMS tags, script-src CDN paths,
    etc.) and — crucially — works even when Wappalyzer isn't installed.

    Args:
        headers: dict-like mapping of lowercase header name → value, OR a list
                 of {"name","value"} records as parsed by parse_http_output.
        html:    response body as a string (safe to pass "" if unavailable).

    Returns:
        list of {"name","version","category"} dicts. Names are canonical.
    """
    hmap = {}
    if isinstance(headers, dict):
        hmap = {str(k).lower(): str(v) for k, v in headers.items()}
    elif isinstance(headers, list):
        for entry in headers:
            if isinstance(entry, dict):
                name = str(entry.get("name", "")).lower()
                if name:
                    hmap[name] = str(entry.get("value", ""))

    body = (html or "")[:65536]  # cap body scan at 64KB
    lowered_body = body.lower()

    techs = []
    seen = set()

    def add(name, version="", category="technology"):
        key = (name.lower(), version)
        if key in seen or not name:
            return
        seen.add(key)
        techs.append({"name": name, "version": version, "category": category})

    # ---- Cookie-based signals ----
    set_cookie_lines = []
    for hname, hval in hmap.items():
        if hname in {"set-cookie", "cookie"}:
            set_cookie_lines.append(hval)
    cookie_blob = " ".join(set_cookie_lines).lower()

    if "jsessionid" in cookie_blob:
        add("Java", category="language")
        add("JSP", category="technology")
    if "phpsessid" in cookie_blob:
        add("PHP", category="language")
    if "asp.net_sessionid" in cookie_blob or "aspsessionid" in cookie_blob:
        add("ASP.NET", category="framework")
    if "laravel_session" in cookie_blob:
        add("Laravel", category="framework")
    if "ci_session" in cookie_blob:
        add("CodeIgniter", category="framework")
    if "django" in cookie_blob and ("sessionid" in cookie_blob or "csrftoken" in cookie_blob):
        add("Django", category="framework")
    if "connect.sid" in cookie_blob:
        add("Express", category="framework")
    if "wordpress_" in cookie_blob or "wp-settings" in cookie_blob:
        add("WordPress", category="cms")

    # ---- Header-based signals ----
    xpb = hmap.get("x-powered-by", "")
    if xpb:
        if "php" in xpb.lower():
            m = re.search(r"php/?\s*([0-9.]+)", xpb, re.IGNORECASE)
            add("PHP", m.group(1) if m else "", "language")
        if "asp.net" in xpb.lower():
            add("ASP.NET", "", "framework")
        if "express" in xpb.lower():
            add("Express", "", "framework")
        if "next.js" in xpb.lower():
            add("Next.js", "", "framework")

    if "x-aspnet-version" in hmap:
        add("ASP.NET", hmap["x-aspnet-version"], "framework")
    if "x-drupal-cache" in hmap or "x-drupal-dynamic-cache" in hmap:
        add("Drupal", category="cms")
    if "x-generator" in hmap:
        add(hmap["x-generator"].split(";")[0].strip(), category="cms")
    if "x-varnish" in hmap:
        add("Varnish", category="technology")
    if "cf-ray" in hmap or "cf-cache-status" in hmap:
        add("Cloudflare", category="technology")
    if "x-fastly-request-id" in hmap or "fastly-io-info" in hmap:
        add("Fastly", category="technology")
    if "x-amz-cf-id" in hmap or "x-amz-cf-pop" in hmap:
        add("Amazon CloudFront", category="technology")
    if "x-akamai-transformed" in hmap or "akamai" in hmap.get("server", "").lower():
        add("Akamai", category="technology")

    via = hmap.get("via", "").lower()
    if "varnish" in via:
        add("Varnish", category="technology")
    if "cloudfront" in via:
        add("Amazon CloudFront", category="technology")

    # ---- HTML body signals ----
    if lowered_body:
        # <meta name="generator" content="...">
        for gen_val in re.findall(
            r'<meta[^>]+name=["\']generator["\'][^>]+content=["\']([^"\']+)["\']',
            body, re.IGNORECASE,
        ):
            add(gen_val.strip().split(" ")[0], category="cms")

        # Script CDNs with versions (jquery/bootstrap/…)
        for m in re.finditer(
            r'src=["\'][^"\']*?(jquery|bootstrap|angular|react|vue|lodash|moment|d3|chart\.?js|'
            r'popper|slick|swiper|fontawesome)[^"\']*?[\-/](\d+\.\d+(?:\.\d+)?)',
            body, re.IGNORECASE,
        ):
            name_map = {
                "jquery": ("jQuery", "library"),
                "bootstrap": ("Bootstrap", "library"),
                "angular": ("Angular", "framework"),
                "react": ("React", "framework"),
                "vue": ("Vue.js", "framework"),
                "lodash": ("Lodash", "library"),
                "moment": ("Moment.js", "library"),
                "d3": ("D3.js", "library"),
                "chart.js": ("Chart.js", "library"),
                "chartjs": ("Chart.js", "library"),
                "popper": ("Popper.js", "library"),
                "slick": ("Slick", "library"),
                "swiper": ("Swiper", "library"),
                "fontawesome": ("Font Awesome", "library"),
            }
            key = m.group(1).lower()
            canonical, cat = name_map.get(key, (m.group(1), "library"))
            add(canonical, m.group(2), cat)

        # Analytics / tag managers
        if "googletagmanager.com/gtm.js" in lowered_body or "gtm-" in lowered_body:
            add("Google Tag Manager", category="technology")
        if "google-analytics.com/analytics.js" in lowered_body or re.search(
            r"ga\s*\(\s*['\"]create['\"]", body
        ):
            add("Google Universal Analytics", category="technology")
        if "googletagmanager.com/gtag/js" in lowered_body or "gtag(" in body:
            add("Google Analytics (GA4)", category="technology")
        if "hotjar" in lowered_body:
            add("Hotjar", category="technology")
        if "mixpanel" in lowered_body:
            add("Mixpanel", category="technology")
        if "segment.com" in lowered_body or "analytics.js" in lowered_body and "segment" in lowered_body:
            add("Segment", category="technology")

        # CMS heuristics from body
        if "/wp-content/" in lowered_body or "/wp-includes/" in lowered_body:
            add("WordPress", category="cms")
        if "drupal-settings-json" in lowered_body or "/sites/default/files/" in lowered_body:
            add("Drupal", category="cms")
        if "/media/jui/" in lowered_body or "joomla" in lowered_body:
            add("Joomla", category="cms")
        if "shopify" in lowered_body and "cdn.shopify.com" in lowered_body:
            add("Shopify", category="cms")

        # Language/framework heuristics from link/form actions
        if re.search(r'(?:href|action|src)=["\'][^"\']+\.jsp(?:\?|["\'])', body, re.IGNORECASE):
            add("JSP", category="technology")
            add("Java", category="language")
        if re.search(r'(?:href|action|src)=["\'][^"\']+\.php(?:\?|["\'])', body, re.IGNORECASE):
            add("PHP", category="language")
        if re.search(r'(?:href|action|src)=["\'][^"\']+\.aspx?(?:\?|["\'])', body, re.IGNORECASE):
            add("ASP.NET", category="framework")

        # HTML5 doctype
        if re.match(r'\s*<!doctype\s+html\s*>', body, re.IGNORECASE):
            add("HTML5", category="technology")

    return techs


def split_product_version(product_field):
    if not product_field:
        return "", ""

    match = re.match(r"(?P<product>.*?)(?:\s+(?P<version>\d[\w.\-]*))?$", product_field.strip())
    if not match:
        return product_field.strip(), ""
    return match.group("product").strip(), (match.group("version") or "").strip()


def extract_version(value):
    match = re.search(r"\d[\w.\-]*", value or "")
    return match.group(0) if match else ""


def _canonicalise_tech_name(name, value):
    """Map noisy WhatWeb-emitted names to canonical labels and decide whether
    the captured value should be treated as a software version.

    Returns:
        (canonical_name, value, suppress_version)
    """
    lowered = name.lower().strip()
    # Analytics tags carry tracker IDs, not versions
    if lowered in {"google-analytics", "google_analytics", "googleanalytics"}:
        return "Google Universal Analytics", value, True
    if lowered in {"google-tag-manager", "googletagmanager", "google_tag_manager"}:
        return "Google Tag Manager", value, True
    if lowered in {"facebook-pixel", "facebookpixel"}:
        return "Facebook Pixel", value, True
    if lowered in {"hotjar"}:
        return "Hotjar", value, True
    if lowered in {"mixpanel"}:
        return "Mixpanel", value, True
    return name, value, False


def categorize_technology(name):
    lowered = name.lower()
    if lowered in {"wordpress", "drupal", "joomla"}:
        return "cms"
    if lowered in {"react", "vue.js", "angular", "next.js"}:
        return "framework"
    if lowered in {"jquery", "bootstrap"}:
        return "library"
    if lowered in {"php", "python", "ruby"}:
        return "language"
    return "technology"


def _is_useful_technology(name, value):
    lowered = name.lower()
    if lowered in WHATWEB_IGNORE_NAMES:
        return False
    if name.startswith("//"):
        return False
    # Reject names with stray brackets — these come from the old bracket-unaware
    # splitter and signal that we grabbed a fragment of a header-list.
    if name.endswith("]") or name.endswith("["):
        return False
    if re.fullmatch(r"\d+m", lowered):
        return False
    if not re.search(r"[A-Za-z]", name):
        return False
    if re.fullmatch(r"\d+(?:\s+\d+)*", name.strip()):
        return False
    # Reject obvious HTTP header names: lowercase, hyphenated, no version/space info
    if re.fullmatch(r"x-[a-z0-9\-]+", lowered):
        return False
    # Reject MIME types
    if "/" in lowered and lowered.split("/", 1)[0] in {"text", "application", "image", "audio", "video"}:
        return False
    lowered_value = (value or "").lower()
    if lowered_value in {"200", "ok", "0m", "0m 0s", "0m 1s"}:
        return False
    return True


def _split_whatweb_line(line):
    """Split a whatweb body line on commas that are NOT inside [ ... ] brackets.

    WhatWeb emits constructs like:
        HTTPServer[nginx], UncommonHeaders[x-cache,x-timer,1.1 varnish], Cookies[foo,bar]
    A naive split on "," would chop ``UncommonHeaders[...]`` into fragments and
    treat each header name as a separate technology. This splitter keeps each
    bracketed group intact.
    """
    segments = []
    depth = 0
    start = 0
    for idx, ch in enumerate(line):
        if ch == "[":
            depth += 1
        elif ch == "]":
            depth = max(0, depth - 1)
        elif ch == "," and depth == 0:
            piece = line[start:idx].strip()
            if piece:
                segments.append(piece)
            start = idx + 1
    tail = line[start:].strip()
    if tail:
        segments.append(tail)
    return segments


def _parse_whatweb_segment(segment):
    if "[" in segment:
        name, remainder = segment.split("[", 1)
        value = remainder.rsplit("]", 1)[0]
        return name.strip(), value.strip()
    return segment.strip(), ""
