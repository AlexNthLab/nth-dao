import type {
  Agent,
  BlackboardData,
  Mission,
  Skill,
  Summary,
  CombinedState,
  NTHMessage,
  Task,
  Announcement,
} from "./types";

const BASE = "";

async function get<T>(path: string): Promise<T> {
  const res = await fetch(`${BASE}${path}`);
  if (!res.ok) throw new Error(`${res.status} ${await res.text()}`);
  return res.json() as T;
}

async function post<T>(path: string, body: unknown): Promise<T> {
  const res = await fetch(`${BASE}${path}`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(body),
  });
  if (!res.ok) throw new Error(`${res.status} ${await res.text()}`);
  return res.json() as T;
}

async function patch<T>(path: string, body: unknown): Promise<T> {
  const res = await fetch(`${BASE}${path}`, {
    method: "PATCH",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(body),
  });
  if (!res.ok) throw new Error(`${res.status} ${await res.text()}`);
  return res.json() as T;
}

// Read-only
export const api = {
  summary: () => get<Summary>("/api/summary"),
  agents: () => get<{ count: number; agents: Agent[] }>("/api/team"),
  blackboard: () => get<BlackboardData>("/api/blackboard"),
  missions: () => get<{ count: number; missions: Mission[] }>("/api/missions"),
  mission: (id: string) => get<Mission>(`/api/missions/${encodeURIComponent(id)}`),
  skills: () => get<{ count: number; skills: Skill[] }>("/api/skills"),

  // Read-write
  state: (agentId = "admin", channelId = "general") =>
    get<CombinedState>(
      `/api/state?agent_id=${encodeURIComponent(agentId)}&channel_id=${encodeURIComponent(channelId)}`,
    ),

  join: (agentId: string, channelId = "general") =>
    post<{ ok: boolean }>("/api/join", { agent_id: agentId, channel_id: channelId }),

  sendMessage: (agentId: string, body: string, channelId = "general") =>
    post<NTHMessage>("/api/messages", {
      agent_id: agentId,
      channel_id: channelId,
      body,
    }),

  createTask: (
    createdBy: string,
    title: string,
    description: string,
    assigneeId = "",
    channelId = "general",
  ) =>
    post<Task>("/api/tasks", {
      created_by: createdBy,
      title,
      description,
      assignee_id: assigneeId,
      channel_id: channelId,
    }),

  updateTask: (taskId: string, status: string, actorId: string, note = "") =>
    patch<Task>(`/api/tasks/${encodeURIComponent(taskId)}`, {
      status,
      actor_id: actorId,
      note,
    }),

  postAnnouncement: (authorId: string, title: string, body: string, channelId = "general") =>
    post<Announcement>("/api/announcements", {
      author_id: authorId,
      title,
      body,
      channel_id: channelId,
    }),
};
