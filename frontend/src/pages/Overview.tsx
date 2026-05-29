import { useSummary, useAgents, useBlackboard, useMissions, useSkills } from "../hooks/useAPI";
import { useNavigate } from "react-router-dom";
import type { Agent, Bucket } from "../api/types";

export default function Overview() {
  const summary = useSummary();
  const agents = useAgents();
  const board = useBlackboard();
  const missions = useMissions();
  const skills = useSkills();
  const nav = useNavigate();

  return (
    <div className="p-6 space-y-6 max-w-7xl mx-auto">
      {/* Stats row */}
      <div className="grid grid-cols-4 gap-4">
        <StatCard
          label="Agents Online"
          value={summary.data?.agents_online ?? "—"}
          color="text-green-400"
          onClick={() => nav("/agents")}
        />
        <StatCard
          label="Active Missions"
          value={summary.data?.missions_active ?? "—"}
          color="text-blue-400"
          onClick={() => nav("/missions")}
        />
        <StatCard
          label="Board Entries"
          value={summary.data?.blackboard_entries ?? "—"}
          color="text-yellow-400"
          onClick={() => nav("/kanban")}
        />
        <StatCard
          label="Skills"
          value={skills.data?.count ?? "—"}
          color="text-purple-400"
        />
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        {/* Recent agents */}
        <Panel title="👥 Online Agents">
          {agents.data?.agents.slice(0, 5).map((a) => (
            <AgentRow key={a.agent_id} agent={a} />
          ))}
          {agents.data?.agents.length === 0 && <Empty>No agents online</Empty>}
        </Panel>

        {/* Kanban preview */}
        <Panel title="📋 Kanban Preview">
          <div className="grid grid-cols-4 gap-2 text-xs">
            {(["todo", "doing", "done", "blocked"] as Bucket[]).map((b) => (
              <div key={b}>
                <div className={`uppercase font-semibold mb-2 ${bucketColor(b)}`}>
                  {b} ({board.data?.buckets[b]?.length ?? 0})
                </div>
                {board.data?.buckets[b]?.slice(0, 3).map((e) => (
                  <div key={e.id} className="bg-gray-800 rounded p-1.5 mb-1 truncate">
                    {e.topic}
                  </div>
                ))}
              </div>
            ))}
          </div>
        </Panel>

        {/* Missions preview */}
        <Panel title="📦 Active Missions">
          {missions.data?.missions.slice(0, 5).map((m) => (
            <div
              key={m.id}
              className="flex items-center justify-between py-1.5 border-b border-gray-800 last:border-0"
            >
              <div>
                <span className="font-mono text-xs text-gray-500 mr-2">{m.id.slice(0, 8)}</span>
                <span>{m.title}</span>
              </div>
              <ProgressBar pct={m.progress.percent} />
            </div>
          ))}
          {missions.data?.missions.length === 0 && <Empty>No active missions</Empty>}
        </Panel>

        {/* Skills preview */}
        <Panel title="📚 Skill Registry">
          {skills.data?.skills.slice(0, 6).map((s) => (
            <div
              key={s.name}
              className="flex items-center justify-between py-1 border-b border-gray-800 last:border-0 text-sm"
            >
              <code className="text-gray-300">{s.name}</code>
              {s.risk && <RiskTag risk={s.risk} />}
            </div>
          ))}
          {skills.data?.skills.length === 0 && <Empty>No skills indexed</Empty>}
        </Panel>
      </div>
    </div>
  );
}

/* ─── Reusable mini-components ─────────────────────────── */

function StatCard({
  label,
  value,
  color,
  onClick,
}: {
  label: string;
  value: number | string;
  color: string;
  onClick?: () => void;
}) {
  return (
    <div
      className={`bg-gray-900 border border-gray-800 rounded-lg p-4 ${onClick ? "cursor-pointer hover:border-gray-600 transition-colors" : ""}`}
      onClick={onClick}
    >
      <div className={`text-2xl font-bold ${color} tabular-nums`}>{value}</div>
      <div className="text-xs text-gray-500 mt-1">{label}</div>
    </div>
  );
}

function Panel({ title, children }: { title: string; children: React.ReactNode }) {
  return (
    <div className="bg-gray-900 border border-gray-800 rounded-lg p-4">
      <h2 className="text-sm font-semibold uppercase text-gray-400 mb-3 tracking-wide">
        {title}
      </h2>
      {children}
    </div>
  );
}

function AgentRow({ agent }: { agent: Agent }) {
  return (
    <div className="flex items-center gap-2 py-1.5 border-b border-gray-800 last:border-0 text-sm">
      <span className={`w-2 h-2 rounded-full ${agent.alive ? "bg-green-500" : "bg-gray-600"}`} />
      <code className="text-gray-300">{agent.agent_id}</code>
      <span className="text-gray-500 text-xs ml-auto">{agent.status}</span>
    </div>
  );
}

function ProgressBar({ pct }: { pct: number }) {
  return (
    <div className="w-24 h-1.5 bg-gray-800 rounded-full overflow-hidden">
      <div
        className="h-full bg-green-500 rounded-full transition-all"
        style={{ width: `${pct}%` }}
      />
    </div>
  );
}

function RiskTag({ risk }: { risk: string }) {
  const color =
    risk === "high" ? "text-red-400 bg-red-950" : risk === "medium" ? "text-yellow-400 bg-yellow-950" : "text-green-400 bg-green-950";
  return (
    <span className={`text-[10px] px-1.5 py-0.5 rounded font-medium ${color}`}>
      {risk}
    </span>
  );
}

function Empty({ children }: { children: React.ReactNode }) {
  return <div className="text-gray-600 text-sm italic py-4 text-center">{children}</div>;
}

function bucketColor(b: Bucket): string {
  return b === "todo" ? "text-yellow-400" : b === "doing" ? "text-blue-400" : b === "done" ? "text-green-400" : "text-red-400";
}
