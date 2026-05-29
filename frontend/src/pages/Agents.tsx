import { useAgents } from "../hooks/useAPI";
import type { Agent } from "../api/types";

export default function Agents() {
  const { data, loading, error } = useAgents();

  return (
    <div className="p-6 max-w-5xl mx-auto">
      <h2 className="text-lg font-semibold mb-4">👥 Agents</h2>

      {loading && <Spinner />}
      {error && <Error msg={error} />}

      {data && (
        <div className="bg-gray-900 border border-gray-800 rounded-lg overflow-hidden">
          <table className="w-full text-sm">
            <thead>
              <tr className="border-b border-gray-800 text-left text-gray-500 text-xs uppercase">
                <th className="p-3 w-8"> </th>
                <th className="p-3">Agent ID</th>
                <th className="p-3">Host</th>
                <th className="p-3">Backend</th>
                <th className="p-3">Status</th>
                <th className="p-3">Mission</th>
                <th className="p-3">Capabilities</th>
              </tr>
            </thead>
            <tbody>
              {data.agents.map((a) => (
                <tr key={a.agent_id} className="border-b border-gray-800 last:border-0 hover:bg-gray-800/50">
                  <td className="p-3">
                    <span className={`w-2 h-2 rounded-full inline-block ${a.alive ? "bg-green-500" : "bg-gray-600"}`} />
                  </td>
                  <td className="p-3">
                    <code className="text-gray-300">{a.agent_id}</code>
                  </td>
                  <td className="p-3 text-gray-500">{a.hostname}</td>
                  <td className="p-3">
                    <Tag>{a.backend_id}</Tag>
                  </td>
                  <td className="p-3">
                    <StatusBadge status={a.status} />
                  </td>
                  <td className="p-3 text-gray-500 truncate max-w-[200px]">
                    {a.current_mission ?? "—"}
                  </td>
                  <td className="p-3">
                    <div className="flex flex-wrap gap-1">
                      {a.capabilities.map((c) => (
                        <Tag key={c}>{c}</Tag>
                      ))}
                    </div>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </div>
  );
}

function Tag({ children }: { children: string }) {
  return (
    <span className="inline-block px-2 py-0.5 rounded text-[11px] font-medium bg-gray-800 text-gray-400">
      {children}
    </span>
  );
}

function StatusBadge({ status }: { status: Agent["status"] }) {
  const map: Record<string, string> = {
    idle: "bg-gray-700 text-gray-300",
    busy: "bg-blue-900 text-blue-300",
    blocked: "bg-red-900 text-red-300",
    offline: "bg-gray-800 text-gray-500",
  };
  return (
    <span className={`inline-block px-2 py-0.5 rounded text-[11px] font-medium ${map[status] ?? "bg-gray-800"}`}>
      {status}
    </span>
  );
}

function Spinner() {
  return <div className="text-gray-500 py-8 text-center animate-pulse">Loading…</div>;
}

function Error({ msg }: { msg: string }) {
  return <div className="text-red-400 bg-red-950/30 border border-red-900 rounded p-3 text-sm">{msg}</div>;
}
