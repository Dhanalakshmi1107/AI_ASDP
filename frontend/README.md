# AI_ASDP Frontend

This frontend is the React + Vite dashboard for AI_ASDP.

## What It Does

- Accepts a target domain from the user
- Sends a scan request to the Flask backend at `POST /start-scan`
- Shows scan progress in the left panel
- Renders scan results in the right panel
- Stores the latest scan result and recent scan history in `localStorage`

## UI Layout

- Left panel:
  - scan form
  - scan progress
  - recent scans
- Right panel:
  - dashboard results
  - metrics cards
  - findings table
  - AI insights

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

- The frontend now uses a single-page layout.
- Results appear on the same page after a scan completes.
