export default function Dashboard({ data, history = [], isScanning = false }) {
  if (isScanning && !data) {
    return (
      <div className="flex min-h-[320px] items-center justify-center rounded-2xl border border-dashed border-gray-700 bg-[#111827] text-gray-400">
        Scanning target...
      </div>
    );
  }

  if (!data) {
    return (
      <div className="flex min-h-[320px] items-center justify-center rounded-2xl border border-dashed border-gray-700 bg-[#111827] text-gray-400">
        Run a scan to see results
      </div>
    );
  }

  return (
    <div className="space-y-8">
      <div>
        <h1 className="text-3xl font-bold text-white">Scan Results</h1>
        <p className="text-gray-400">Target: {data.target}</p>
      </div>

      <div className="rounded-2xl border border-gray-700 bg-[#1e293b] p-5">
        <h3 className="mb-3 font-semibold">Recent Scans</h3>
        <ul className="space-y-1 text-sm text-gray-300">
          {history.length > 0 ? (
            history.map((item, i) => (
              <li key={`${item.target}-${item.time}-${i}`}>
                {item.target} - {item.time}
              </li>
            ))
          ) : (
            <li>No recent scans</li>
          )}
        </ul>
      </div>

      <div className="grid grid-cols-1 gap-6 md:grid-cols-2 xl:grid-cols-4">
        <Card title="Subdomains" value={data.subdomains?.length || 0} />
        <Card title="Open Ports" value={data.open_ports?.length || 0} />
        <Card title="Technologies" value={data.technologies?.length || 0} />
        <Card title="Potential CVEs" value={data.cves?.length || 0} highlight />
      </div>

      <div className="grid gap-6 xl:grid-cols-2">
        <Box title="Subdomains">
          {data.subdomains?.length > 0 ? (
            data.subdomains.map((subdomain, i) => <li key={i}>- {subdomain}</li>)
          ) : (
            <li>No subdomains found</li>
          )}
        </Box>

        <div className="rounded-2xl border border-gray-700 bg-[#1e293b] p-5">
          <h3 className="mb-4 font-semibold">Findings</h3>

          <div className="overflow-x-auto">
            <table className="w-full min-w-[420px] border-collapse text-sm">
              <thead className="text-gray-400">
                <tr>
                  <th className="pb-3 text-left">Host</th>
                  <th className="pb-3 text-left">Port</th>
                  <th className="pb-3 text-left">Service</th>
                  <th className="pb-3 text-left">Risk</th>
                </tr>
              </thead>
              <tbody>
                {data.findings?.length > 0 ? (
                  data.findings.map((finding, i) => (
                    <tr key={i} className="border-t border-gray-700">
                      <td className="py-3">{finding.host}</td>
                      <td className="py-3">{finding.port}</td>
                      <td className="py-3">{finding.service}</td>
                      <td className="py-3 text-yellow-400">{finding.risk}</td>
                    </tr>
                  ))
                ) : (
                  <tr className="border-t border-gray-700">
                    <td className="py-3 text-gray-400" colSpan="4">
                      No findings
                    </td>
                  </tr>
                )}
              </tbody>
            </table>
          </div>
        </div>
      </div>

      <Box title="AI Insights">
        {data.ai_insights?.length > 0 ? (
          data.ai_insights.map((insight, idx) => <li key={idx}>- {insight}</li>)
        ) : (
          <li>No insights yet</li>
        )}
      </Box>
    </div>
  );
}

function Card({ title, value, highlight = false }) {
  return (
    <div className="rounded-2xl border border-gray-700 bg-[#1e293b] p-6">
      <p className="text-sm text-gray-400">{title}</p>
      <h2 className={`text-2xl font-semibold ${highlight ? "text-red-400" : "text-white"}`}>
        {value}
      </h2>
    </div>
  );
}

function Box({ title, children }) {
  return (
    <div className="rounded-2xl border border-gray-700 bg-[#1e293b] p-5">
      <h3 className="mb-4 font-semibold">{title}</h3>
      <ul className="space-y-1 text-sm text-gray-300">{children}</ul>
    </div>
  );
}
