export default function RecentScans({ history = [] }) {
  return (
    <div className="rounded-xl border border-gray-700 bg-[#1e293b] p-4">
      <h3 className="mb-3 font-semibold">Recent Scans</h3>

      <ul className="space-y-2 text-sm">
        {history.length > 0 ? (
          history.map((item, i) => (
            <li key={`${item.target}-${item.time}-${i}`} className="flex justify-between gap-3">
              <span className="truncate">{item.target}</span>
              <span className="shrink-0 text-xs text-gray-400">{item.time}</span>
            </li>
          ))
        ) : (
          <li className="text-gray-400">No scans yet</li>
        )}
      </ul>
    </div>
  );
}
