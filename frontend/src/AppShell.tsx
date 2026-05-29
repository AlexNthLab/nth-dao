import { NavLink, Outlet } from "react-router-dom";
import { useSummary } from "./hooks/useAPI";

const NAV = [
  { to: "/overview", label: "Overview", icon: "⚡" },
  { to: "/agents", label: "Agents", icon: "👥" },
  { to: "/kanban", label: "Kanban", icon: "📋" },
  { to: "/missions", label: "Missions", icon: "📦" },
  { to: "/chat", label: "Chat", icon: "💬" },
];

export default function AppShell() {
  const { data } = useSummary();

  return (
    <div className="min-h-screen flex flex-col">
      {/* Top bar */}
      <header className="h-14 flex items-center gap-4 px-6 bg-gray-900 border-b border-gray-800 shrink-0">
        <h1 className="text-lg font-bold tracking-tight">NTH DAO Console</h1>
        <nav className="flex gap-1 ml-4">
          {NAV.map((n) => (
            <NavLink
              key={n.to}
              to={n.to}
              className={({ isActive }) =>
                `px-3 py-1.5 rounded-md text-sm font-medium transition-colors ${
                  isActive
                    ? "bg-gray-700 text-white"
                    : "text-gray-400 hover:text-gray-200 hover:bg-gray-800"
                }`
              }
            >
              <span className="mr-1">{n.icon}</span>
              {n.label}
            </NavLink>
          ))}
        </nav>
        <div className="ml-auto flex items-center gap-5 text-xs text-gray-500">
          {data && (
            <>
              <Metric value={data.agents_online} label="agents" />
              <Metric value={data.missions_active} label="missions" />
              <Metric value={data.blackboard_entries} label="board" />
            </>
          )}
          <span className="text-gray-600">v{data?.version ?? "—"}</span>
        </div>
      </header>

      {/* Page content */}
      <main className="flex-1 overflow-auto">
        <Outlet />
      </main>
    </div>
  );
}

function Metric({ value, label }: { value: number; label: string }) {
  return (
    <div className="flex flex-col items-center">
      <span className="text-base font-bold text-blue-400 tabular-nums">
        {value}
      </span>
      <span className="text-[10px] text-gray-500 uppercase">{label}</span>
    </div>
  );
}
