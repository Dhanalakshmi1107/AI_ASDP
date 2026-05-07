import { useEffect, useState } from "react";

export default function RecentScans({ onLoadScan }) {
  const [scans, setScans] = useState([]);
  const [loadingId, setLoadingId] = useState(null);
  const [error, setError] = useState(null);

  // Fetch scan history from the API on mount
  useEffect(() => {
    fetch("/scan-history")
      .then((res) => res.json())
      .then((data) => setScans(Array.isArray(data) ? data : []))
      .catch(() => setError("Could not load scan history"));
  }, []);

  const handleLoad = async (scanId) => {
    setLoadingId(scanId);
    try {
      const res = await fetch(`/scan/${scanId}`);
      const data = await res.json();
      if (data && data.target) {
        // Persist to localStorage so it survives a page refresh
        localStorage.setItem("scanResult", JSON.stringify(data.result_json ?? data));
        onLoadScan?.(data.result_json ?? data);
      }
    } catch {
      setError(`Failed to load scan ${scanId}`);
    } finally {
      setLoadingId(null);
    }
  };

  return (
    <div className="rounded-xl border border-gray-700 bg-[#1e293b] p-4">
      <h3 className="mb-3 font-semibold">Recent Scans</h3>

      {error && <p className="mb-2 text-xs text-red-400">{error}</p>}

      <ul className="space-y-2 text-sm">
        {scans.length > 0 ? (
          scans.slice(0, 10).map((item) => (
            <li key={item.id}>
              <button
                onClick={() => handleLoad(item.id)}
                disabled={loadingId === item.id}
                className="flex w-full items-center justify-between gap-3 rounded-lg px-2 py-1.5 text-left transition hover:bg-[#0f172a] disabled:opacity-50"
                title={`Load scan #${item.id}`}
              >
                <span className="truncate text-gray-200">{item.target}</span>
                <div className="flex shrink-0 flex-col items-end gap-0.5">
                  <span className="text-xs text-gray-400">
                    {formatTimestamp(item.timestamp)}
                  </span>
                  {item.risk_score != null && (
                    <span className={`text-xs font-semibold ${riskColor(item.risk_score)}`}>
                      {item.risk_score}
                    </span>
                  )}
                </div>
                {loadingId === item.id && (
                  <span className="ml-1 shrink-0 text-xs text-blue-400">loading…</span>
                )}
              </button>
            </li>
          ))
        ) : (
          <li className="text-gray-400">No scans yet</li>
        )}
      </ul>
    </div>
  );
}

function riskColor(score) {
  if (score >= 70) return "text-red-400";
  if (score >= 40) return "text-yellow-300";
  return "text-green-400";
}

function formatTimestamp(value) {
  if (!value) return "";
  const d = new Date(value);
  return Number.isNaN(d.getTime()) ? value : d.toLocaleString();
}
