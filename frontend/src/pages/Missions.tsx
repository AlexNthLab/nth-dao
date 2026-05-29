import { useMissions } from "../hooks/useAPI";
import { useState } from "react";
import { api } from "../api/client";
import type { Mission } from "../api/types";

export default function Missions() {
  const { data, loading, error } = useMissions();
  const [detail, setDetail] = useState<Mission | null>(null);
  const [detailLoading, setDetailLoading] = useState(false);

  async function loadDetail(id: string) {
    setDetailLoading(true);
    try {
      const m = await api.mission(id);
      setDetail(m);
    } catch {
      setDetail(null);
    } finally {
      setDetailLoading(false);
    }
  }

  return (
    <div className="p-6 max-w-6xl mx-auto">
      <h2 className="text-lg font-semibold mb-4">📦 Missions</h2>

      {loading && <div className="text-gray-500 py-8 text-center animate-pulse">Loading…</div>}
      {error && <div className="text-red-400 bg-red-950/30 border border-red-900 rounded p-3 text-sm">{error}</div>}

      {data && (
        <div className="grid grid-cols-1 lg:grid-cols-3 gap-4">
          <div className="lg:col-span-1 space-y-2">
            {data.missions.map((m) => (
              <button
                key={m.id}
                onClick={() => loadDetail(m.id)}
                className={`w-full text-left p-3 rounded-lg border transition-colors ${
                  detail?.id === m.id
                    ? "bg-gray-800 border-blue-600"
                    : "bg-gray-900 border-gray-800 hover:border-gray-600"
                }`}
              >
                <div className="font-medium text-sm">{m.title}</div>
                <div className="flex items-center gap-2 mt-1 text-xs text-gray-500">
                  <span className="font-mono">{m.id.slice(0, 8)}</span>
                  <span>·</span>
                  <StatusBadge s={m.status} />
                  <span className="ml-auto">{m.progress.done}/{m.progress.total}</span>
                </div>
                <div className="w-full h-1 bg-gray-700 rounded-full mt-2 overflow-hidden">
                  <div
                    className="h-full bg-green-500 transition-all"
                    style={{ width: `${m.progress.percent}%` }}
                  />
                </div>
              </button>
            ))}
            {data.missions.length === 0 && (
              <div className="text-gray-600 text-sm italic text-center py-8">No active missions</div>
            )}
          </div>

          <div className="lg:col-span-2">
            {detailLoading && <div className="text-gray-500 py-8 text-center animate-pulse">Loading details…</div>}
            {!detail && !detailLoading && (
              <div className="text-gray-600 text-sm italic text-center py-8">
                Select a mission to view details
              </div>
            )}
            {detail && (
              <div className="bg-gray-900 border border-gray-800 rounded-lg p-4 space-y-4">
                <div>
                  <h3 className="font-semibold text-lg">{detail.title}</h3>
                  {detail.goal && <p className="text-sm text-gray-400 mt-1">{detail.goal}</p>}
                  <div className="flex gap-3 mt-2 text-xs text-gray-500">
                    <span>owner: <code>{detail.owner}</code></span>
                    <span>scope: <code>{detail.scope}</code></span>
                    <span>priority: {detail.priority}</span>
                    <StatusBadge s={detail.status} />
                  </div>
                </div>

                {detail.steps && detail.steps.length > 0 && (
                  <div>
                    <h4 className="text-sm font-semibold text-gray-400 uppercase mb-2">Steps</h4>
                    <div className="space-y-2">
                      {detail.steps.map((s) => (
                        <div
                          key={s.id}
                          className="flex items-start gap-3 bg-gray-800 rounded p-3 text-sm"
                        >
                          <span
                            className={`w-2 h-2 rounded-full mt-1.5 shrink-0 ${
                              s.status === "done"
                                ? "bg-green-500"
                                : s.status === "in_progress"
                                  ? "bg-blue-500"
                                  : "bg-gray-600"
                            }`}
                          />
                          <div className="flex-1">
                            <div className="text-gray-200">{s.description}</div>
                            <div className="flex gap-2 mt-1 text-[11px] text-gray-500">
                              <span>{s.status}</span>
                              {s.assignee && <span>· {s.assignee}</span>}
                              {s.depends_on.length > 0 && (
                                <span>· depends: {s.depends_on.join(", ")}</span>
                              )}
                            </div>
                          </div>
                        </div>
                      ))}
                    </div>
                  </div>
                )}
              </div>
            )}
          </div>
        </div>
      )}
    </div>
  );
}

function StatusBadge({ s }: { s: string }) {
  const colors: Record<string, string> = {
    active: "bg-green-900 text-green-300",
    completed: "bg-blue-900 text-blue-300",
    blocked: "bg-red-900 text-red-300",
    pending: "bg-yellow-900 text-yellow-300",
  };
  return (
    <span
      className={`inline-block px-2 py-0.5 rounded text-[11px] font-medium ${colors[s] ?? "bg-gray-800 text-gray-400"}`}
    >
      {s}
    </span>
  );
}
