# AI_ASDP

AI_ASDP is an AI-Based Attack Surface Discovery Platform built with a React + Vite frontend and a Flask backend. The platform runs reconnaissance tools against a target domain, normalizes the output into JSON, and presents the results in a single-page dashboard.

## Current Stack

- Frontend: React, Vite, Tailwind CSS
- Backend: Flask with CORS enabled
- Recon tools: Nmap, Subfinder, WhatWeb
- Runtime flow: Flask executes recon tools -> returns JSON -> React stores results in `localStorage` -> dashboard updates on the same page

## Current UI Flow

The frontend now uses a single-page split layout:

- Left panel:
  - Start New Scan form
  - Scan progress
  - Recent scans
- Right panel:
  - Dashboard results
  - Summary cards
  - Findings table
  - AI insights

When a user clicks `Start Scan`:

1. The button changes to `Scanning...`
2. A request is sent to `POST /start-scan`
3. The backend returns structured scan data
4. The frontend saves the latest result and scan history to `localStorage`
5. The right-side dashboard updates without page navigation

## Current Backend Response

The backend returns JSON in this format:

```json
{
  "target": "example.com",
  "subdomains": [],
  "open_ports": [],
  "technologies": [],
  "findings": [],
  "cves": [],
  "ai_insights": []
}
```

## Project Structure

```text
AI_ASDP/
|-- main.py
|-- requirements.txt
|-- frontend/
|   |-- src/
|   |   |-- components/
|   |   |-- pages/
|   |   |-- App.jsx
|   |   `-- index.css
|   |-- package.json
|   `-- vite.config.js
`-- README.md
```

## Prerequisites

Make sure these are installed and available in your PATH:

- Python 3.x
- Node.js and npm
- Nmap
- Subfinder
- WhatWeb
- Wafw00f
- SSL Scan 
- Wappalyzer

## Backend Setup

From the project root:

```bash
python -m venv venv
```

Activate the virtual environment:

```bash
# Linux / WSL
source venv/bin/activate

# Windows PowerShell
venv\Scripts\Activate.ps1
```

Install backend dependencies:

```bash
pip install -r requirements.txt
```

Start Flask:

```bash
python main.py
```

The backend runs on:

```text
http://127.0.0.1:5000
```

## Frontend Setup

From the `frontend` folder:

```bash
npm install
npm run dev
```

The Vite app runs on:

```text
http://localhost:5173
```

## Running the Full App

1. Start the Flask backend from the project root.
2. Start the Vite frontend from the `frontend` folder.
3. Open `http://localhost:5173`.
4. Enter a target domain and start a scan.

## Notes

- The frontend is currently designed to stay on one page instead of navigating between routes.
- Tailwind is integrated through the Vite plugin configuration.
- Scan history and the latest results are persisted in browser `localStorage`.
- The backend currently includes basic parsing and sample AI insight generation logic.

## Current Status

This repository is no longer just a blank prototype. It now includes:

- working Flask scan endpoint
- working React single-page dashboard
- persistent recent scan history
- split-panel tool-style UI
- Tailwind + Vite frontend styling pipeline

## Author

Dhanalakshmi Sathyanarayanan  
Ethical Hacking Project  
AI-Based Attack Surface Discovery Platform
