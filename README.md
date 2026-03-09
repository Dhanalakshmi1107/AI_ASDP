# AI-Based Attack Surface Discovery Platform

## Overview

This project aims to develop an AI-assisted platform that helps identify
the exposed attack surface of a target application. The system
integrates multiple reconnaissance tools to collect information about
subdomains, open ports, services, SSL/TLS configurations, WAF presence,
and server technologies. The collected data is structured into a unified
format and will later be analyzed using an AI model to highlight
potential risks and areas for further security testing.

This repository currently contains the **initial development
prototype**

------------------------------------------------------------------------

## Features (Current Stage)

-   Basic UI to input a target domain and initiate a scan
------------------------------------------------------------------------

## Planned Features

-   CVE database integration for vulnerability lookup
-   AI-based analysis of reconnaissance results
-   Attack surface summary generation
-   Automated report generation (HTML/Text)
-   Improved user interface and visualization

------------------------------------------------------------------------

## Requirements

-   Python 3.x
-   Nmap
-   Subfinder
-   SSLScan
-   WafW00f
-   WhatWeb
-   Wappalyzer

Make sure all tools are installed and accessible from the system PATH.

------------------------------------------------------------------------

## Running the Project (Development)

1.  Clone the repository
2.  Execute these commands
```bash
git clone <repo_url>
cd 
python -m venv venv
source venv/bin/activate # for linux
venv\Scripts\activate # for windows
python main.py
```

------------------------------------------------------------------------

## Current Status

This is an **early development version** of the project. Features and
architecture may change as the system evolves.

------------------------------------------------------------------------

## Author
Dhanalakshmi Sathyanarayanan\
Ethical Hacking Project\
AI-Based Attack Surface Discovery Platform