import { useState } from "react";

export default function RagChat({ target, scanId }) {
  const [query, setQuery] = useState("");
  const [answer, setAnswer] = useState(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState(null);

  const handleSubmit = async (event) => {
    event.preventDefault();

    const trimmedQuery = query.trim();
    if (!trimmedQuery) {
      setError("Enter a question to query this scan.");
      return;
    }

    setLoading(true);
    setError(null);

    try {
      const response = await fetch("/rag-query", {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
        },
        body: JSON.stringify({
          query: trimmedQuery,
          target,
          scan_id: scanId,
        }),
      });

      const payload = await response.json();
      if (!response.ok) {
        throw new Error(payload.error || "RAG query failed.");
      }

      setAnswer(payload);
    } catch (err) {
      console.error(err);
      setError(err.message || "RAG query failed.");
    } finally {
      setLoading(false);
    }
  };

  const confidenceClassName = getConfidenceClassName(answer?.confidence);
  const sources = Array.isArray(answer?.sources) ? answer.sources : [];

  return (
    <div className="rounded-2xl border border-gray-700 bg-[#1e293b] p-5">
      <h3 className="mb-4 font-semibold">Ask about this scan</h3>

      <form onSubmit={handleSubmit} className="space-y-4">
        <div className="flex flex-col gap-3 sm:flex-row">
          <input
            type="text"
            value={query}
            onChange={(event) => setQuery(event.target.value)}
            placeholder="Ask anything about this scan..."
            className="flex-1 rounded-lg border border-gray-600 bg-[#0f172a] px-4 py-3 text-sm text-white focus:border-blue-500 focus:outline-none"
          />
          <button
            type="submit"
            disabled={loading}
            className="rounded-lg bg-blue-600 px-5 py-3 text-sm font-semibold text-white transition hover:bg-blue-700 disabled:cursor-not-allowed disabled:opacity-60"
          >
            {loading ? "Thinking..." : "Ask"}
          </button>
        </div>
      </form>

      {error ? <p className="mt-4 text-sm text-red-400">{error}</p> : null}

      {answer ? (
        <div className="mt-5 space-y-4 rounded-xl border border-gray-700 bg-[#111827] p-4">
          <div>
            <span
              className={`inline-flex rounded-full px-3 py-1 text-xs font-semibold uppercase ${confidenceClassName}`}
            >
              Confidence: {answer.confidence || "low"}
            </span>
          </div>

          <p className="text-sm leading-6 text-gray-200">{answer.answer}</p>

          <details className="text-sm text-gray-300">
            <summary className="cursor-pointer font-medium text-white">
              Sources ({sources.length})
            </summary>
            <ul className="mt-3 space-y-2">
              {sources.length > 0 ? (
                sources.map((source, index) => (
                  <li key={`${source.collection}-${index}`} className="rounded-lg border border-gray-700 bg-[#0f172a] p-3">
                    <p className="font-medium text-white">{source.collection}</p>
                    <p className="mt-1 text-gray-400">{source.snippet}</p>
                  </li>
                ))
              ) : (
                <li className="text-gray-400">No sources returned</li>
              )}
            </ul>
          </details>
        </div>
      ) : null}
    </div>
  );
}

function getConfidenceClassName(confidence) {
  if (confidence === "high") {
    return "bg-green-500/20 text-green-200";
  }

  if (confidence === "medium") {
    return "bg-yellow-500/20 text-yellow-200";
  }

  return "bg-gray-500/20 text-gray-200";
}
