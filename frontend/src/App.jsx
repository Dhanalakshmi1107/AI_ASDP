import { useEffect, useState } from "react";
import ScanForm from "./components/ScanForm";
import ScanProgress from "./components/ScanProgress";
import RecentScans from "./components/RecentScans";
import Dashboard from "./pages/Dashboard";

export default function App() {
  const [scanResult, setScanResult] = useState(null);
  const [scanHistory, setScanHistory] = useState([]);
  const [isScanning, setIsScanning] = useState(false);

  useEffect(() => {
    const storedResult = localStorage.getItem("scanResult");
    const storedHistory = localStorage.getItem("scanHistory");

    if (storedResult) {
      setScanResult(JSON.parse(storedResult));
    }

    if (storedHistory) {
      setScanHistory(JSON.parse(storedHistory));
    }
  }, []);

  const handleScanComplete = (data, history) => {
    setScanResult(data);
    setScanHistory(history);
  };

  return (
    <div className="min-h-screen bg-[#0f172a] text-[#e2e8f0]">
      <div className="mx-auto flex min-h-screen w-full max-w-[1600px] flex-col lg:flex-row">
        <aside className="w-full border-b border-gray-800 p-6 lg:w-[360px] lg:flex-shrink-0 lg:border-b-0 lg:border-r">
          <div className="space-y-6">
            <ScanForm
              onScanStart={() => setIsScanning(true)}
              onScanComplete={(data, history) => {
                handleScanComplete(data, history);
                setIsScanning(false);
              }}
              onScanError={() => setIsScanning(false)}
            />
            <ScanProgress isScanning={isScanning} hasResults={Boolean(scanResult)} />
            <RecentScans history={scanHistory} />
          </div>
        </aside>

        <main className="flex-1 overflow-y-auto p-6 lg:p-8">
          <Dashboard data={scanResult} history={scanHistory} isScanning={isScanning} />
        </main>
      </div>
    </div>
  );
}
