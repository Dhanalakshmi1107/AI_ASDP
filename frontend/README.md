# AI_ASDP Frontend

This frontend is the single-page React + Vite dashboard for AI_ASDP.

## What It Displays

The dashboard consumes the schema-driven backend response and displays:

- target and scan timestamp
- recent scans
- subdomain count
- discovered service count
- detected technologies
- mapped CVEs
- subdomains list
- technologies list
- host overview
- findings table with CVEs per service
- AI analysis summary, risks, and recommendations

## UI Layout

- Left panel:
  - scan form
  - scan progress
  - recent scans
- Right panel:
  - scan results
  - cards
  - technologies
  - CVE summary
  - findings
  - AI analysis

## Frontend Data Flow

1. User enters a target and starts a scan.
2. Frontend sends `POST /start-scan` to the Flask backend.
3. Backend returns a schema-valid JSON response.
4. Frontend stores the latest result in `localStorage`.
5. Dashboard updates on the same page without navigation.

## Scripts

```bash
npm install
npm run dev
npm run build
```

## Tech

- React
- Vite
- Tailwind CSS

## Notes

- The frontend uses a single-page split layout.
- Tailwind is integrated through the Vite plugin.
- The browser tab title is `AI_ASDP`.
- The dashboard expects the backend to follow `Master_Recon_Schema.json`.
