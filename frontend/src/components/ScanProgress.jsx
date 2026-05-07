export default function ScanProgress({ isScanning, hasResults, progressText }) {
  return (
    <div className="rounded-xl border border-gray-700 bg-[#1e293b] p-4">
      <h3 className="mb-2 font-semibold">Scan Progress</h3>

      {isScanning ? (
        <div className="space-y-2">
          {/* Animated progress bar */}
          <div className="h-1.5 w-full overflow-hidden rounded-full bg-gray-700">
            <div className="h-full animate-pulse rounded-full bg-blue-500" style={{ width: "100%" }} />
          </div>
          <p className="text-sm text-blue-400">
            {progressText || "Running reconnaissance…"}
          </p>
        </div>
      ) : (
        <p className="text-sm text-gray-400">
          {hasResults ? "Latest scan completed successfully." : "Start a scan to see progress."}
        </p>
      )}
    </div>
  );
}
