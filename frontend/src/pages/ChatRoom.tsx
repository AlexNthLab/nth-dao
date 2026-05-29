import { useState, useRef, useEffect } from "react";
import { useCombinedState } from "../hooks/useAPI";
import { api } from "../api/client";
import type { NTHMessage, Task, Announcement } from "../api/types";

export default function ChatRoom() {
  const [agentId, setAgentId] = useState("admin");
  const [channelId, setChannelId] = useState("general");
  const [input, setInput] = useState("");

  const { data, loading, error } = useCombinedState(agentId, channelId);
  const messagesEnd = useRef<HTMLDivElement>(null);

  useEffect(() => {
    messagesEnd.current?.scrollIntoView({ behavior: "smooth" });
  }, [data?.messages.length]);

  async function handleSend() {
    const body = input.trim();
    if (!body) return;
    setInput("");
    try {
      await api.sendMessage(agentId, body, channelId);
    } catch (e) {
      console.error(e);
    }
  }

  return (
    <div className="h-[calc(100vh-56px)] flex">
      {/* Left sidebar — channels + members */}
      <aside className="w-60 bg-gray-900 border-r border-gray-800 flex flex-col shrink-0">
        {/* Agent identity */}
        <div className="p-3 border-b border-gray-800">
          <input
            value={agentId}
            onChange={(e) => setAgentId(e.target.value)}
            className="w-full bg-gray-800 border border-gray-700 rounded px-2 py-1.5 text-sm text-gray-200 outline-none focus:border-blue-600"
            placeholder="agent_id"
          />
        </div>

        {/* Channels */}
        <div className="p-3 border-b border-gray-800">
          <div className="text-[10px] text-gray-500 uppercase tracking-wider mb-2 font-semibold">
            Channels
          </div>
          {data?.channels.map((ch) => (
            <button
              key={ch.channel_id}
              onClick={() => setChannelId(ch.channel_id)}
              className={`w-full text-left px-2 py-1.5 rounded text-sm mb-0.5 transition-colors ${
                ch.channel_id === channelId
                  ? "bg-blue-900/40 text-blue-300"
                  : "text-gray-400 hover:bg-gray-800"
              }`}
            >
              # {ch.name}
            </button>
          ))}
        </div>

        {/* Members */}
        <div className="flex-1 overflow-y-auto p-3">
          <div className="text-[10px] text-gray-500 uppercase tracking-wider mb-2 font-semibold">
            Members
          </div>
          {data?.members.map((m) => (
            <div
              key={m.agent_id}
              className="flex items-center gap-2 py-1 text-sm cursor-pointer hover:bg-gray-800 px-1 rounded"
              onClick={() => setAgentId(m.agent_id)}
            >
              <span className={`w-2 h-2 rounded-full ${m.online ? "bg-green-500" : "bg-gray-600"}`} />
              <span className="text-gray-300">{m.agent_id}</span>
              <span className="text-[10px] text-gray-600 ml-auto">{m.role}</span>
            </div>
          ))}
        </div>
      </aside>

      {/* Center — messages */}
      <section className="flex-1 flex flex-col min-w-0">
        {/* Channel header */}
        <div className="h-12 flex items-center px-4 border-b border-gray-800 bg-gray-900 shrink-0">
          <span className="font-semibold text-sm"># {channelId}</span>
          {data && (
            <span className="text-xs text-gray-600 ml-3">
              {data.messages.length} messages
            </span>
          )}
        </div>

        {/* Messages */}
        <div className="flex-1 overflow-y-auto px-4 py-3 space-y-3">
          {loading && <div className="text-gray-500 text-center animate-pulse py-8">Loading…</div>}
          {error && <div className="text-red-400 bg-red-950/30 rounded p-3 text-sm">{error}</div>}

          {data?.messages.map((msg) => (
            <MessageBubble key={msg.message_id} msg={msg} isMine={msg.sender_id === agentId} />
          ))}
          {data?.messages.length === 0 && !loading && (
            <div className="text-gray-600 text-sm italic text-center py-8">
              No messages yet. Send one!
            </div>
          )}
          <div ref={messagesEnd} />
        </div>

        {/* Composer */}
        <div className="p-3 border-t border-gray-800 bg-gray-900 flex gap-2 shrink-0">
          <input
            value={input}
            onChange={(e) => setInput(e.target.value)}
            onKeyDown={(e) => e.key === "Enter" && handleSend()}
            className="flex-1 bg-gray-800 border border-gray-700 rounded px-3 py-2 text-sm text-gray-200 outline-none focus:border-blue-600"
            placeholder={`Message #${channelId}...`}
          />
          <button
            onClick={handleSend}
            className="px-4 py-2 bg-blue-600 hover:bg-blue-500 rounded text-sm font-medium transition-colors"
          >
            Send
          </button>
        </div>
      </section>

      {/* Right sidebar — announcements + tasks */}
      <aside className="w-72 bg-gray-900 border-l border-gray-800 overflow-y-auto shrink-0 p-3 space-y-4">
        {/* Announcements */}
        <section>
          <div className="text-[10px] text-gray-500 uppercase tracking-wider mb-2 font-semibold">
            Announcements
          </div>
          {data?.announcements.map((a) => (
            <AnnouncementCard key={a.announcement_id} ann={a} />
          ))}
          {data?.announcements.length === 0 && (
            <div className="text-gray-600 text-xs italic">None</div>
          )}
        </section>

        {/* Tasks */}
        <section>
          <div className="text-[10px] text-gray-500 uppercase tracking-wider mb-2 font-semibold">
            Tasks
          </div>
          {data?.tasks.map((t) => (
            <TaskCard key={t.task_id} task={t} agentId={agentId} />
          ))}
          {data?.tasks.length === 0 && (
            <div className="text-gray-600 text-xs italic">None</div>
          )}
        </section>
      </aside>
    </div>
  );
}

/* ─── Sub-components ───────────────────────────────────────── */

function MessageBubble({ msg, isMine }: { msg: NTHMessage; isMine: boolean }) {
  const time = new Date(msg.created_at).toLocaleTimeString("en-US", {
    hour: "2-digit",
    minute: "2-digit",
    hour12: false,
  });

  return (
    <div className={`flex flex-col ${isMine ? "items-end" : "items-start"}`}>
      <div className={`max-w-[70%] rounded-lg px-3 py-2 text-sm ${
        isMine ? "bg-blue-600 text-white" : "bg-gray-800 text-gray-200"
      }`}>
        {!isMine && (
          <div className="text-[10px] text-blue-400 font-medium mb-0.5">{msg.sender_id}</div>
        )}
        <div className="whitespace-pre-wrap break-words">{msg.body}</div>
      </div>
      <div className="text-[10px] text-gray-600 mt-0.5 px-1">{time}</div>
    </div>
  );
}

function AnnouncementCard({ ann }: { ann: Announcement }) {
  return (
    <div className="bg-gray-800 rounded p-2 mb-2 text-xs">
      <div className="font-medium text-gray-200">{ann.title}</div>
      <div className="text-gray-400 mt-0.5 line-clamp-2">{ann.body}</div>
      <div className="text-[10px] text-gray-600 mt-1">{ann.author_id}</div>
    </div>
  );
}

function TaskCard({ task, agentId }: { task: Task; agentId: string }) {
  const color: Record<string, string> = {
    open: "border-yellow-700 bg-yellow-950/20",
    accepted: "border-blue-700 bg-blue-950/20",
    running: "border-green-700 bg-green-950/20",
    blocked: "border-red-700 bg-red-950/20",
    completed: "border-gray-700 bg-gray-950/30",
    cancelled: "border-gray-700 bg-gray-950/30",
  };

  async function update(status: string) {
    try {
      await api.updateTask(task.task_id, status, agentId);
    } catch (e) {
      console.error(e);
    }
  }

  return (
    <div className={`border rounded p-2 mb-2 text-xs ${color[task.status] ?? "border-gray-700"}`}>
      <div className="font-medium text-gray-200">{task.title}</div>
      {task.description && (
        <div className="text-gray-500 mt-0.5 line-clamp-2">{task.description}</div>
      )}
      <div className="flex items-center gap-2 mt-1.5">
        <span className={`text-[10px] px-1.5 py-0.5 rounded uppercase font-medium ${
          task.status === "completed" ? "bg-gray-700 text-gray-400" :
          task.status === "blocked" ? "bg-red-900 text-red-300" :
          "bg-gray-800 text-gray-400"
        }`}>
          {task.status}
        </span>
        {task.assignee_id && (
          <span className="text-gray-600">{task.assignee_id}</span>
        )}
        {task.status !== "completed" && task.status !== "cancelled" && (
          <select
            onChange={(e) => update(e.target.value)}
            defaultValue=""
            className="ml-auto bg-gray-800 border border-gray-700 rounded text-[10px] px-1 py-0.5 text-gray-400"
          >
            <option value="" disabled>Update</option>
            <option value="running">Running</option>
            <option value="blocked">Blocked</option>
            <option value="completed">Complete</option>
            <option value="cancelled">Cancel</option>
          </select>
        )}
      </div>
    </div>
  );
}
