// ─── Agent ────────────────────────────────────────────────────────
//  Source: nth_dao.discovery.AgentRecord

export interface Agent {
  agent_id: string;
  hostname: string;
  pid: number;
  backend_id: string;
  capabilities: string[];
  groups: string[];
  status: "idle" | "busy" | "blocked" | "offline";
  current_mission: string | null;
  last_seen: string; // ISO 8601
  alive: boolean;
}

// ─── Blackboard ───────────────────────────────────────────────────
//  Source: team_layer.blackboard.BlackboardEntry

export type Bucket = "todo" | "doing" | "done" | "blocked" | "other";

export interface BlackboardEntry {
  id: string;
  scope: string;
  topic: string;
  author: string;
  status: Bucket;
  content: string;
  updated_at: string;
  metadata: Record<string, unknown>;
}

export interface BlackboardData {
  total: number;
  buckets: Record<Bucket, BlackboardEntry[]>;
}

// ─── Mission ──────────────────────────────────────────────────────
//  Source: nth_dao.orchestration.{Mission, MissionStep, MissionStatus}

export interface MissionStep {
  id: string;
  description: string;
  status: string;
  assignee: string | null;
  previous_assignees: string[];
  depends_on: string[];
  notes: string[];
  completed_at: string | null;
}

export interface Mission {
  id: string;
  title: string;
  goal?: string;
  status: string;
  owner: string;
  scope: string;
  priority: string;
  progress: { done: number; total: number; percent: number };
  step_count: number;
  created_at: string;
  updated_at?: string;
  steps?: MissionStep[];
}

// ─── Team ─────────────────────────────────────────────────────────
//  Source: nth_dao.membership.{TeamConfig, TeamRole}

export type JoinPolicy = "open" | "approval" | "invite_only" | "token";
export type TeamRole = "owner" | "admin" | "member" | "guest";

export interface TeamConfig {
  team_id: string;
  team_name: string;
  join_policy: JoinPolicy;
  join_token: string;
  admin_ids: string[];
  member_ids: string[];
  roles: Record<string, TeamRole>;
  created_at: string;
  metadata: Record<string, unknown>;
}

export interface Member {
  agent_id: string;
  role: TeamRole;
  online: boolean;
}

// ─── Channel & Messages ───────────────────────────────────────────
//  Source: nth_dao.groups.{Channel, Message, MessageKind}

export type MessageKind = "text" | "command" | "system";

export interface Channel {
  channel_id: string;
  name: string;
  topic: string;
  created_by: string;
  is_private: boolean;
  member_ids: string[];
  created_at: string;
  metadata: Record<string, unknown>;
}

export interface NTHMessage {
  message_id: string;
  channel_id: string;
  sender_id: string;
  body: string;
  kind: MessageKind;
  reply_to: string;
  created_at: string;
  metadata: Record<string, unknown>;
}

// ─── Task ─────────────────────────────────────────────────────────
//  Source: nth_dao.groups.{Task, TaskStatus}

export type TaskStatus =
  | "open"
  | "accepted"
  | "running"
  | "blocked"
  | "completed"
  | "cancelled";

export interface Task {
  task_id: string;
  title: string;
  description: string;
  created_by: string;
  assignee_id: string;
  channel_id: string;
  status: TaskStatus;
  due_at: string;
  created_at: string;
  updated_at: string;
  metadata: Record<string, unknown>;
}

// ─── Announcement ─────────────────────────────────────────────────
//  Source: nth_dao.groups.Announcement

export interface Announcement {
  announcement_id: string;
  title: string;
  body: string;
  author_id: string;
  channel_id: string;
  pinned: boolean;
  created_at: string;
  metadata: Record<string, unknown>;
}

// ─── Audit ────────────────────────────────────────────────────────
//  Source: nth_dao.groups.AuditEvent

export interface AuditEvent {
  event_id: string;
  event_type: string;
  actor_id: string;
  target_type: string;
  target_id: string;
  summary: string;
  created_at: string;
  metadata: Record<string, unknown>;
}

// ─── Summary ──────────────────────────────────────────────────────

export interface Summary {
  agents_online: number;
  missions_active: number;
  blackboard_entries: number;
  server_time: string;
  version: string;
}

// ─── Combined State ───────────────────────────────────────────────
//  Source: GET /api/state

export interface CombinedState {
  team: TeamConfig;
  role: TeamRole;
  members: Member[];
  channels: Channel[];
  messages: NTHMessage[];
  announcements: Announcement[];
  tasks: Task[];
  audit: AuditEvent[];
}

// ─── Skills ───────────────────────────────────────────────────────

export interface Skill {
  name: string;
  desc?: string;
  risk?: string;
  error_sig?: string;
  raw_preview: string;
}
