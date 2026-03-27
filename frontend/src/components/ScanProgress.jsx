export default function ScanProgress({ isScanning, hasResults }) {
  return (
    <div className="rounded-xl border border-gray-700 bg-[#1e293b] p-4">
      <h3 className="mb-2 font-semibold">Scan Progress</h3>
      <p className="text-sm text-gray-400">
        {isScanning
          ? "Running reconnaissance..."
          : hasResults
            ? "Latest scan completed successfully."
            : "Start a scan to see progress."}
      </p>
    </div>
  );
}
