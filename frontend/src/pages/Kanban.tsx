import { useBlackboard } from "../hooks/useAPI";
import type { BlackboardEntry, Bucket } from "../api/types";

const COLS: { key: Bucket; label: string; emoji: string; color: string }[] = [
  { key: "todo", label: "TODO", emoji: "📋", color: "border-yellow-600" },
  { key: "doing", label: "DOING", emoji: "🔨", color: "border-blue-600" },
  { key: "done", label: "DONE", emoji: "✅", color: "border-green-600" },
  { key: "blocked", label: "BLOCKED", emoji: "🚧", color: "border-red-600" },
];

export default function Kanban() {
  const { data, loading, error } = useBlackboard();

  return (
    <div className="p-6">
      <h2 className="text-lg font-semibold mb-4">📋 Kanban</h2>

      {loading && <div className="text-gray-500 py-8 text-center animate-pulse">Loading…</div>}
      {error && <div className="text-red-400 bg-red-950/30 border border-red-900 rounded p-3 text-sm">{error}</div>}

      {data && (
        <div className="grid grid-cols-4 gap-3 h-[calc(100vh-140px)]">
          {COLS.map((col) => (
            <div key={col.key} className="bg-gray-900 border border-gray-800 rounded-lg flex flex-col">
              <div className={`px-3 py-2 border-b-2 ${col.color} font-semibold text-sm`}>
                {col.emoji} {col.label}{" "}
                <span className="text-gray-500 text-xs ml-1">
                  ({data.buckets[col.key]?.length ?? 0})
                </span>
              </div>
              <div className="flex-1 overflow-y-auto p-2 space-y-2">
                {data.buckets[col.key]?.slice(0, 50).map((entry) => (
                  <KanbanCard key={entry.id} entry={entry} />
                ))}
                {(!data.buckets[col.key] || data.buckets[col.key].length === 0) && (
                  <div className="text-gray-700 text-xs italic text-center py-4">Empty</div>
                )}
              </div>
            </div>
          ))}
        </div>
      )}
    </div>
  );
}

function KanbanCard({ entry }: { entry: BlackboardEntry }) {
  return (
    <div className="bg-gray-800 border border-gray-700 rounded-md p-2.5 text-sm">
      <div className="font-medium text-gray-200 truncate">{entry.topic}</div>
      <div className="text-[11px] text-gray-500 mt-1 flex flex-wrap gap-x-2">
        <span>{entry.author}</span>
        <span className="text-gray-600">·</span>
        <span>{entry.scope}</span>
      </div>
    </div>
  );
}
