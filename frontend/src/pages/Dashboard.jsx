import { useState } from "react";
import RagChat from "../components/RagChat";

const SEVERITY_STYLES = {
  CRITICAL: "bg-red-900 text-red-300 border-red-700",
  HIGH:     "bg-orange-900 text-orange-300 border-orange-700",
  MEDIUM:   "bg-yellow-900 text-yellow-200 border-yellow-700",
  LOW:      "bg-green-900 text-green-300 border-green-700",
};

const SEVERITY_DOT = {
  CRITICAL: "bg-red-400",
  HIGH:     "bg-orange-400",
  MEDIUM:   "bg-yellow-400",
  LOW:      "bg-green-400",
};

export default function Dashboard({ data, history = [], isScanning = false }) {
  const [activeTab, setActiveTab] = useState("overview");

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

  const subdomains = Array.isArray(data.subdomains) ? data.subdomains : [];
  const hosts = Array.isArray(data.hosts) ? data.hosts : [];
  const services = hosts.flatMap((host) =>
    (host.services || []).map((service) => ({ ...service, hostname: host.hostname }))
  );
  const technologies = dedupeTechnologies(hosts);
  const cves = dedupeCves(services);
  const aiAnalysis = normalizeAiAnalysis(data.ai_analysis);
  const ragExecutiveSummary = data.rag_analysis?.stage4_synthesis?.executive_summary || "";
  const riskScore = normalizeRiskScore(data.risk_score);

  const pentestPlan = data.pentest_plan || null;
  const attackVectors = pentestPlan?.attack_vectors || [];
  const excludedVectors = pentestPlan?.excluded || [];
  const criticSummary = pentestPlan?.critic_summary || null;
  const attackCount = attackVectors.length;

  const tabs = [
    { id: "overview", label: "Overview" },
    { id: "pentest",  label: `Pentest Plan${attackCount ? ` (${attackCount})` : ""}` },
    { id: "chat",     label: "AI Chat" },
  ];

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex flex-wrap items-start justify-between gap-4">
        <div>
          <h1 className="text-3xl font-bold text-white">Scan Results</h1>
          <p className="text-gray-400">Target: {data.target}</p>
          <p className="text-sm text-gray-500">Scanned at: {formatTimestamp(data.scan_timestamp)}</p>
        </div>

        {data.scan_id && (
          <a
            href={`/export-md/${data.scan_id}`}
            download
            className="flex items-center gap-2 rounded-lg border border-gray-600 bg-[#1e293b] px-4 py-2 text-sm text-gray-300 transition hover:border-blue-500 hover:text-white"
            title="Download attacksurface.md"
          >
            <span>⬇</span> Export .md
          </a>
        )}
      </div>

      {/* Recent scans */}
      <div className="rounded-2xl border border-gray-700 bg-[#1e293b] p-5">
        <h3 className="mb-3 font-semibold">Scan Log</h3>
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

      {/* Summary cards */}
      <div className="grid grid-cols-1 gap-6 md:grid-cols-2 xl:grid-cols-5">
        <Card title="Subdomains"          value={subdomains.length} />
        <Card title="Discovered Services" value={services.length} />
        <Card title="Technologies"        value={technologies.length} />
        <Card title="Mapped CVEs"         value={cves.length} highlight />
        <Card title="Risk Score"          value={riskScore.label} valueClassName={riskScore.className} />
      </div>

      {/* Tab bar */}
      <div className="flex border-b border-gray-700">
        {tabs.map((tab) => (
          <button
            key={tab.id}
            onClick={() => setActiveTab(tab.id)}
            className={`px-5 py-3 text-sm font-medium transition ${
              activeTab === tab.id
                ? "border-b-2 border-blue-500 text-white"
                : "text-gray-400 hover:text-gray-200"
            }`}
          >
            {tab.label}
          </button>
        ))}
      </div>

      {/* Tab content */}
      {activeTab === "overview" && (
        <OverviewTab
          subdomains={subdomains}
          technologies={technologies}
          hosts={hosts}
          cves={cves}
          services={services}
          aiAnalysis={aiAnalysis}
          ragExecutiveSummary={ragExecutiveSummary}
        />
      )}

      {activeTab === "pentest" && (
        <PentestPlanTab
          attackVectors={attackVectors}
          excludedVectors={excludedVectors}
          criticSummary={criticSummary}
        />
      )}

      {activeTab === "chat" && (
        <RagChat target={data.target} scanId={data.scan_id ?? null} />
      )}
    </div>
  );
}

// ---------------------------------------------------------------------------
// Overview tab (original content)
// ---------------------------------------------------------------------------

function OverviewTab({ subdomains, technologies, hosts, cves, services, aiAnalysis, ragExecutiveSummary }) {
  return (
    <div className="space-y-8">
      <div className="grid gap-6 xl:grid-cols-2">
        <Box title="Subdomains">
          {subdomains.length > 0 ? (
            subdomains.map((subdomain) => (
              <li key={subdomain.name}>
                {subdomain.name}
                {subdomain.ip ? ` (${subdomain.ip})` : ""}
                {subdomain.status ? ` - ${subdomain.status}` : ""}
              </li>
            ))
          ) : (
            <li>No subdomains found</li>
          )}
        </Box>

        <Box title="Technologies">
          {technologies.length > 0 ? (
            technologies.map((tech) => (
              <li key={`${tech.name}-${tech.version}-${tech.category}`}>
                {tech.name}
                {tech.version ? ` ${tech.version}` : ""}
                {tech.category ? ` - ${tech.category}` : ""}
              </li>
            ))
          ) : (
            <li>No technologies detected</li>
          )}
        </Box>
      </div>

      <div className="grid gap-6 xl:grid-cols-2">
        <HostOverview hosts={hosts} />
        <CveSummary cves={cves} />
      </div>

      <FindingsTable services={services} />

      <AiAnalysisCard aiAnalysis={aiAnalysis} ragExecutiveSummary={ragExecutiveSummary} />
    </div>
  );
}

// ---------------------------------------------------------------------------
// Pentest Plan tab
// ---------------------------------------------------------------------------

function PentestPlanTab({ attackVectors, excludedVectors, criticSummary }) {
  const [expandedId, setExpandedId] = useState(null);
  const [showExcluded, setShowExcluded] = useState(false);

  const toggle = (id) => setExpandedId(expandedId === id ? null : id);

  return (
    <div className="space-y-6">
      {/* Critic summary bar */}
      {criticSummary && (
        <div className="rounded-2xl border border-gray-700 bg-[#1e293b] p-4">
          <p className="mb-2 text-sm font-semibold text-gray-300">Critic Agent Summary</p>
          <div className="flex flex-wrap gap-4 text-sm">
            <span className="text-gray-400">
              Total proposed: <span className="font-bold text-white">{criticSummary.total}</span>
            </span>
            <span className="text-green-400">
              ✓ Confirmed: <span className="font-bold">{criticSummary.confirmed}</span>
            </span>
            <span className="text-red-400">
              ✗ Rejected: <span className="font-bold">{criticSummary.rejected}</span>
            </span>
            {criticSummary.needs_manual_check > 0 && (
              <span className="text-yellow-400">
                ⚠ Manual check: <span className="font-bold">{criticSummary.needs_manual_check}</span>
              </span>
            )}
          </div>
        </div>
      )}

      {/* No vectors state */}
      {attackVectors.length === 0 && (
        <div className="rounded-2xl border border-dashed border-gray-700 bg-[#111827] p-8 text-center text-gray-400">
          No confirmed attack vectors for this scan.
          {criticSummary?.rejected > 0 && (
            <p className="mt-2 text-sm">
              {criticSummary.rejected} vector{criticSummary.rejected > 1 ? "s were" : " was"} rejected by the critic agent.
            </p>
          )}
        </div>
      )}

      {/* Attack vector cards */}
      {attackVectors.map((av) => {
        const sev = (av.severity || "MEDIUM").toUpperCase();
        const isOpen = expandedId === av.id;
        return (
          <div
            key={av.id}
            className={`rounded-2xl border bg-[#1e293b] ${SEVERITY_STYLES[sev] || "border-gray-700"}`}
          >
            {/* Card header — always visible */}
            <button
              onClick={() => toggle(av.id)}
              className="flex w-full items-center gap-3 px-5 py-4 text-left"
            >
              <span className={`h-2.5 w-2.5 flex-shrink-0 rounded-full ${SEVERITY_DOT[sev] || "bg-gray-400"}`} />
              <span className="flex-1 font-semibold text-white">{av.attack_name}</span>
              <span className={`rounded px-2 py-0.5 text-xs font-bold border ${SEVERITY_STYLES[sev] || "border-gray-700"}`}>
                {sev}
              </span>
              <span className="ml-2 font-mono text-xs text-gray-500">{av.service_key}</span>
              <span className="ml-3 text-gray-400">{isOpen ? "▲" : "▼"}</span>
            </button>

            {/* Expanded detail */}
            {isOpen && (
              <div className="border-t border-gray-700 px-5 pb-5 pt-4 space-y-4 text-sm text-gray-300">
                <p>{av.description}</p>

                <div className="grid gap-4 md:grid-cols-2">
                  {av.mitre_technique && (
                    <Detail label="MITRE ATT&CK">
                      <code className="text-blue-300">{av.mitre_technique}</code>
                    </Detail>
                  )}
                  {av.ports?.length > 0 && (
                    <Detail label="Ports">
                      {av.ports.map((p) => (
                        <code key={p} className="mr-1 rounded bg-[#111827] px-1">{p}</code>
                      ))}
                    </Detail>
                  )}
                  {av.tools?.length > 0 && (
                    <Detail label="Tools">
                      {av.tools.join(", ")}
                    </Detail>
                  )}
                  {av.cve_refs?.length > 0 && (
                    <Detail label="CVE References">
                      {av.cve_refs.join(", ")}
                    </Detail>
                  )}
                </div>

                {av.preconditions?.length > 0 && (
                  <Detail label="Preconditions">
                    <ul className="mt-1 list-inside list-disc space-y-0.5">
                      {av.preconditions.map((p, i) => <li key={i}>{p}</li>)}
                    </ul>
                  </Detail>
                )}

                {av.quick_command && (
                  <Detail label="Quick Command">
                    <pre className="mt-1 overflow-x-auto rounded-lg bg-[#0f172a] p-3 text-xs text-green-300">
                      {av.quick_command}
                    </pre>
                  </Detail>
                )}

                {av.expected_evidence && (
                  <Detail label="Expected Evidence">
                    {av.expected_evidence}
                  </Detail>
                )}

                {av.critic_reasons?.length > 0 && (
                  <Detail label="Critic Notes">
                    <ul className="mt-1 list-inside list-disc space-y-0.5 text-yellow-300">
                      {av.critic_reasons.map((r, i) => <li key={i}>{r}</li>)}
                    </ul>
                  </Detail>
                )}
              </div>
            )}
          </div>
        );
      })}

      {/* Excluded by critic — collapsible section */}
      {excludedVectors.length > 0 && (
        <div className="rounded-2xl border border-gray-700 bg-[#1e293b] p-5">
          <button
            onClick={() => setShowExcluded(!showExcluded)}
            className="flex w-full items-center justify-between text-sm text-gray-400 hover:text-gray-200"
          >
            <span>Excluded by Critic ({excludedVectors.length})</span>
            <span>{showExcluded ? "▲" : "▼"}</span>
          </button>

          {showExcluded && (
            <div className="mt-4 overflow-x-auto">
              <table className="w-full min-w-[600px] border-collapse text-sm">
                <thead className="text-gray-400">
                  <tr>
                    <th className="pb-3 text-left">Attack</th>
                    <th className="pb-3 text-left">Target</th>
                    <th className="pb-3 text-left">Rejected by</th>
                    <th className="pb-3 text-left">Reason</th>
                  </tr>
                </thead>
                <tbody>
                  {excludedVectors.map((ex, i) => (
                    <tr key={i} className="border-t border-gray-700 align-top">
                      <td className="py-2 pr-4 font-medium text-white">{ex.attack_name}</td>
                      <td className="py-2 pr-4 font-mono text-xs text-gray-400">{ex.service_key}</td>
                      <td className="py-2 pr-4 text-gray-400">{ex.rejected_by}</td>
                      <td className="py-2 text-gray-400">{(ex.reasons || []).join("; ")}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </div>
      )}
    </div>
  );
}

function Detail({ label, children }) {
  return (
    <div>
      <p className="mb-1 text-xs font-semibold uppercase tracking-wider text-gray-500">{label}</p>
      <div>{children}</div>
    </div>
  );
}

// ---------------------------------------------------------------------------
// Shared UI components
// ---------------------------------------------------------------------------

function Card({ title, value, highlight = false, valueClassName = "" }) {
  const resolvedClassName = valueClassName || (highlight ? "text-red-400" : "text-white");
  return (
    <div className="rounded-2xl border border-gray-700 bg-[#1e293b] p-6">
      <p className="text-sm text-gray-400">{title}</p>
      <h2 className={`text-2xl font-semibold ${resolvedClassName}`}>{value}</h2>
    </div>
  );
}

function Box({ title, children }) {
  return (
    <div className="rounded-2xl border border-gray-700 bg-[#1e293b] p-5">
      <h3 className="mb-4 font-semibold">{title}</h3>
      <ul className="space-y-2 text-sm text-gray-300">{children}</ul>
    </div>
  );
}

function HostOverview({ hosts }) {
  return (
    <div className="rounded-2xl border border-gray-700 bg-[#1e293b] p-5">
      <h3 className="mb-4 font-semibold">Host Overview</h3>
      {hosts.length > 0 ? (
        <div className="space-y-4 text-sm text-gray-300">
          {hosts.map((host) => (
            <div key={host.hostname} className="rounded-xl border border-gray-700 bg-[#111827] p-4">
              <p className="font-medium text-white">{host.hostname}</p>
              <p className="text-gray-400">{host.ip || "IP not resolved"}</p>
              <p className="mt-2">HTTP Status: {host.http?.status_code || "N/A"}</p>
              <p>WAF: {host.waf?.detected ? host.waf.name || "Detected" : "Not detected"}</p>
              <p>
                TLS:{" "}
                {host.tls?.supported_versions?.length
                  ? host.tls.supported_versions.join(", ")
                  : "No TLS data"}
              </p>
            </div>
          ))}
        </div>
      ) : (
        <p className="text-sm text-gray-400">No hosts discovered</p>
      )}
    </div>
  );
}

function CveSummary({ cves }) {
  return (
    <div className="rounded-2xl border border-gray-700 bg-[#1e293b] p-5">
      <h3 className="mb-4 font-semibold">CVE Summary</h3>
      {cves.length > 0 ? (
        <div className="space-y-3 text-sm text-gray-300">
          {cves.map((cve) => (
            <div key={cve.cve_id} className="rounded-xl border border-gray-700 bg-[#111827] p-4">
              <p className="font-medium text-white">{cve.cve_id}</p>
              <p className="text-gray-400">{cve.description || "No description available"}</p>
              <p className="mt-2">
                Severity: <span className="text-red-300">{cve.severity}</span>
                {" | "}
                CVSS: {cve.cvss_score}
              </p>
            </div>
          ))}
        </div>
      ) : (
        <p className="text-sm text-gray-400">No CVEs mapped yet</p>
      )}
    </div>
  );
}

function FindingsTable({ services }) {
  return (
    <div className="rounded-2xl border border-gray-700 bg-[#1e293b] p-5">
      <h3 className="mb-4 font-semibold">Findings</h3>

      <div className="overflow-x-auto">
        <table className="w-full min-w-[760px] border-collapse text-sm">
          <thead className="text-gray-400">
            <tr>
              <th className="pb-3 text-left">Host</th>
              <th className="pb-3 text-left">Port</th>
              <th className="pb-3 text-left">Protocol</th>
              <th className="pb-3 text-left">Service</th>
              <th className="pb-3 text-left">Product</th>
              <th className="pb-3 text-left">CVEs</th>
            </tr>
          </thead>
          <tbody>
            {services.length > 0 ? (
              services.map((service) => (
                <tr
                  key={`${service.hostname}-${service.port}-${service.protocol}`}
                  className="border-t border-gray-700 align-top"
                >
                  <td className="py-3">{service.hostname}</td>
                  <td className="py-3">{service.port}</td>
                  <td className="py-3">{service.protocol}</td>
                  <td className="py-3">{service.service_name || "unknown"}</td>
                  <td className="py-3">
                    {[service.product, service.version].filter(Boolean).join(" ") || "Unknown"}
                  </td>
                  <td className="py-3">
                    {service.cve_matches?.length > 0 ? (
                      <div className="space-y-2">
                        {service.cve_matches.map((cve) => (
                          <div
                            key={cve.cve_id}
                            className="rounded-lg border border-gray-700 bg-[#111827] p-2"
                          >
                            <p className="font-medium text-white">{cve.cve_id}</p>
                            <p className="text-xs text-gray-400">
                              {cve.severity} | CVSS {cve.cvss_score}
                            </p>
                          </div>
                        ))}
                      </div>
                    ) : (
                      <span className="text-gray-500">No CVEs mapped</span>
                    )}
                  </td>
                </tr>
              ))
            ) : (
              <tr className="border-t border-gray-700">
                <td className="py-3 text-gray-400" colSpan="6">
                  No services discovered
                </td>
              </tr>
            )}
          </tbody>
        </table>
      </div>
    </div>
  );
}

function AiAnalysisCard({ aiAnalysis, ragExecutiveSummary }) {
  return (
    <div className="rounded-2xl border border-gray-700 bg-[#1e293b] p-5">
      <h3 className="mb-4 font-semibold">AI Analysis</h3>
      <p className="mb-4 text-sm text-gray-300">
        {aiAnalysis.summary || "No AI summary available yet."}
      </p>

      {ragExecutiveSummary ? (
        <div className="mb-6 rounded-xl border border-gray-700 bg-[#111827] p-4">
          <h4 className="mb-2 text-sm font-semibold text-white">RAG Executive Summary</h4>
          <p className="text-sm text-gray-300">{ragExecutiveSummary}</p>
        </div>
      ) : null}

      <div className="grid gap-6 xl:grid-cols-2">
        <Box title="Risks">
          {aiAnalysis.risks.length > 0 ? (
            aiAnalysis.risks.map((risk, index) => (
              <li key={`${risk.title}-${index}`}>
                <span className="font-medium text-white">{risk.title}</span>
                {` - ${risk.level}`}
                {risk.details ? ` - ${risk.details}` : ""}
              </li>
            ))
          ) : (
            <li>No risks identified</li>
          )}
        </Box>

        <Box title="Recommendations">
          {aiAnalysis.recommendations.length > 0 ? (
            aiAnalysis.recommendations.map((recommendation, index) => (
              <li key={`${recommendation}-${index}`}>{recommendation}</li>
            ))
          ) : (
            <li>No recommendations available</li>
          )}
        </Box>
      </div>
    </div>
  );
}

// ---------------------------------------------------------------------------
// Pure helpers
// ---------------------------------------------------------------------------

function dedupeTechnologies(hosts) {
  const seen = new Set();
  const technologies = [];

  hosts.forEach((host) => {
    (host.web_stack?.technologies || []).forEach((technology) => {
      const key = `${technology.name}-${technology.version}-${technology.category}`;
      if (!seen.has(key)) {
        seen.add(key);
        technologies.push(technology);
      }
    });
  });

  return technologies;
}

function dedupeCves(services) {
  const seen = new Set();
  const cves = [];

  services.forEach((service) => {
    (service.cve_matches || []).forEach((cve) => {
      if (!seen.has(cve.cve_id)) {
        seen.add(cve.cve_id);
        cves.push(cve);
      }
    });
  });

  return cves;
}

function normalizeAiAnalysis(aiAnalysis) {
  return {
    summary: aiAnalysis?.summary || "",
    risks: Array.isArray(aiAnalysis?.risks) ? aiAnalysis.risks : [],
    recommendations: Array.isArray(aiAnalysis?.recommendations)
      ? aiAnalysis.recommendations
      : [],
  };
}

function normalizeRiskScore(value) {
  if (value === null || value === undefined || Number.isNaN(Number(value))) {
    return { label: "N/A", className: "text-gray-300" };
  }

  const score = Number(value);
  if (score >= 70) {
    return { label: score, className: "text-red-400" };
  }

  if (score >= 40) {
    return { label: score, className: "text-yellow-300" };
  }

  return { label: score, className: "text-green-400" };
}

function formatTimestamp(value) {
  if (!value) {
    return "Unknown";
  }

  const parsed = new Date(value);
  return Number.isNaN(parsed.getTime()) ? value : parsed.toLocaleString();
}
