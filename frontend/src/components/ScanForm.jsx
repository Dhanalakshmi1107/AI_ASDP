import { useState } from "react";

export default function ScanForm({ onScanStart, onScanComplete, onScanError }) {
  const [target, setTarget] = useState("");
  const [mode, setMode] = useState("standard");
  const [loading, setLoading] = useState(false);

  const handleSubmit = async () => {
    if (!target) {
      alert("Enter a target");
      return;
    }

    setLoading(true);
    onScanStart?.();

    try {
      const res = await fetch("http://127.0.0.1:5000/start-scan", {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
        },
        body: JSON.stringify({ target, mode }),
      });

      const data = await res.json();
      localStorage.setItem("scanResult", JSON.stringify(data));

      const history = JSON.parse(localStorage.getItem("scanHistory") || "[]");
      const updatedHistory = [
        {
          target,
          time: new Date().toLocaleString(),
        },
        ...history,
      ].slice(0, 5);

      localStorage.setItem("scanHistory", JSON.stringify(updatedHistory));
      onScanComplete?.(data, updatedHistory);
    } catch (err) {
      console.error(err);
      onScanError?.(err);
    } finally {
      setLoading(false);
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

          <div className="flex gap-8">
            <label className="flex cursor-pointer items-center gap-2">
              <input
                type="radio"
                name="mode"
                checked={mode === "standard"}
                onChange={() => setMode("standard")}
              />
              Standard
            </label>

            <label className="flex cursor-pointer items-center gap-2">
              <input
                type="radio"
                name="mode"
                checked={mode === "deep"}
                onChange={() => setMode("deep")}
              />
              Deep
            </label>
          </div>
        </div>

        <button
          type="submit"
          disabled={loading}
          className="w-full rounded-lg bg-blue-600 p-4 text-lg font-semibold transition hover:bg-blue-700 disabled:opacity-60"
        >
          {loading ? "Scanning..." : "Start Scan"}
        </button>

        {loading && (
          <div className="text-center text-sm text-blue-400">
            Running scan... please wait
          </div>
        )}
      </form>
    </div>
  );
}
