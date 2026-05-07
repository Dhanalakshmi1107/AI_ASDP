import { useRef, useState } from "react";

const POLL_INTERVAL_MS = 4000; // poll every 4 s

export default function ScanForm({ onScanStart, onScanComplete, onScanError, onProgressUpdate }) {
  const [target, setTarget] = useState("");
  const [mode, setMode] = useState("standard");
  const [loading, setLoading] = useState(false);
  const [progressText, setProgressText] = useState("");
  const pollRef = useRef(null);

  const stopPolling = () => {
    if (pollRef.current) {
      clearInterval(pollRef.current);
      pollRef.current = null;
    }
  };

  const handleSubmit = async () => {
    if (!target) {
      alert("Enter a target");
      return;
    }

    setLoading(true);
    setProgressText("Queuing scan…");
    onScanStart?.();
    stopPolling();

    try {
      // POST returns 202 immediately with {scan_id, status, target, mode}
      const res = await fetch("/start-scan", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ target, mode }),
      });

      const initial = await res.json();

      if (!res.ok) {
        // 400 / 403 with an error payload
        const msg = initial.error || "Scan rejected by server";
        setProgressText(msg);
        onScanError?.(new Error(msg));
        setLoading(false);
        return;
      }

      const scanId = initial.scan_id;
      if (!scanId) {
        throw new Error("Server returned no scan_id");
      }

      setProgressText("Scan queued — waiting for worker…");
      onProgressUpdate?.("Scan queued — waiting for worker…");

      // --- Poll /scan-status/:id until terminal state ---
      pollRef.current = setInterval(async () => {
        try {
          const statusRes = await fetch(`/scan-status/${scanId}`);
          const statusData = await statusRes.json();

          const text = statusData.progress_text || statusData.status || "Running…";
          setProgressText(text);
          onProgressUpdate?.(text);

          if (statusData.status === "completed") {
            stopPolling();

            // Fetch full result
            const resultRes = await fetch(`/scan/${scanId}`);
            const resultRow = await resultRes.json();
            const data = resultRow.result_json ?? resultRow;

            localStorage.setItem("scanResult", JSON.stringify(data));

            const history = JSON.parse(localStorage.getItem("scanHistory") || "[]");
            const updatedHistory = [
              { target, time: new Date().toLocaleString() },
              ...history,
            ].slice(0, 5);
            localStorage.setItem("scanHistory", JSON.stringify(updatedHistory));

            setLoading(false);
            setProgressText("Scan complete ✓");
            onScanComplete?.(data, updatedHistory);

          } else if (statusData.status === "failed") {
            stopPolling();
            setLoading(false);
            const errMsg = statusData.progress_text || "Scan failed";
            setProgressText(errMsg);
            onScanError?.(new Error(errMsg));
          }
        } catch (pollErr) {
          console.error("Poll error:", pollErr);
        }
      }, POLL_INTERVAL_MS);

    } catch (err) {
      stopPolling();
      setLoading(false);
      setProgressText("Error connecting to backend");
      console.error(err);
      onScanError?.(err);
    }
  };

  return (
    <div className="w-full rounded-2xl border border-gray-700 bg-[#1e293b] p-6 shadow-xl">
      <h2 className="mb-6 text-center text-2xl font-semibold">Start New Scan</h2>

      <form
        onSubmit={(e) => {
          e.preventDefault();
          handleSubmit();
        }}
        className="space-y-6"
      >
        <input
          type="text"
          placeholder="example.com"
          value={target}
          onChange={(e) => setTarget(e.target.value)}
          className="w-full rounded-lg border border-gray-600 bg-[#0f172a] p-4 text-lg focus:border-blue-500 focus:outline-none"
        />

        <div>
          <p className="mb-3 text-sm text-gray-400">Scan Mode</p>

          <div className="flex flex-wrap gap-6">
            <label className="flex cursor-pointer items-center gap-2" title="No LLM calls — playbook-only, fastest">
              <input type="radio" name="mode" checked={mode === "fast"} onChange={() => setMode("fast")} />
              Fast
            </label>

            <label className="flex cursor-pointer items-center gap-2" title="LLM attack enumeration + critic — recommended">
              <input type="radio" name="mode" checked={mode === "standard"} onChange={() => setMode("standard")} />
              Standard
            </label>

            <label className="flex cursor-pointer items-center gap-2" title="Full Nmap + SSLScan + LLM — most thorough">
              <input type="radio" name="mode" checked={mode === "deep"} onChange={() => setMode("deep")} />
              Deep
            </label>

            <label className="flex cursor-pointer items-center gap-2" title="Discovers all subdomains then scans each one — root domain only">
              <input type="radio" name="mode" checked={mode === "organization"} onChange={() => setMode("organization")} />
              Organization
            </label>
          </div>

          <p className="mt-2 text-xs text-gray-500">
            {mode === "fast" && "Fast: rule-based only, 0 AI calls, ~30 s"}
            {mode === "standard" && "Standard: AI attack enumeration + critic, ~2–3 min"}
            {mode === "deep" && "Deep: full scan + AI + SSL analysis, ~5+ min"}
            {mode === "organization" && "Organization: subfinder → scan up to 10 hosts (root + subdomains), ~10–30 min — root domain only (e.g. example.com)"}
          </p>
        </div>

        <button
          type="submit"
          disabled={loading}
          className="w-full rounded-lg bg-blue-600 p-4 text-lg font-semibold transition hover:bg-blue-700 disabled:opacity-60"
        >
          {loading ? "Scanning…" : "Start Scan"}
        </button>

        {loading && progressText && (
          <div className="text-center text-sm text-blue-400">{progressText}</div>
        )}
      </form>
    </div>
  );
}
