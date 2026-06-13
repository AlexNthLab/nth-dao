import { FormEvent, useEffect, useMemo, useState } from "react";
import {
  createChannel,
  createTask,
  getDaoState,
  getDaos,
  getBuildId,
  getIdentity,
  getSummary,
  join,
  postAnnouncement,
  postMessage,
  updateTaskStatus
} from "./api";
import { ContactShell } from "./panels";
import { type BrowserWallet, loadOrCreateWallet } from "./crypto";
import type { BuildId, NodeIdentity } from "./api";
import type { DaoState, DaoSummary, Summary, TaskStatus } from "./types";

// Week-1 Task 5: the bundle's git/file hash, baked in at vite build
// time via import.meta.url. Pairing this with backend_git lets the
// operator detect drift at a glance.
const BUNDLE_HASH: string = (() => {
  try {
    const url = new URL(import.meta.url);
    const match = url.pathname.match(/index-([A-Za-z0-9_-]+)\.js/);
    return match ? match[1] : "dev";
  } catch {
    return "dev";
  }
})();

const defaultAgent = window.localStorage.getItem("nth-dao-agent-id") || "admin";
const defaultDao = window.localStorage.getItem("nth-dao-active-slug") || "home";
const taskStatuses: TaskStatus[] = ["open", "accepted", "running", "blocked", "completed", "cancelled"];

// DAO-scoped channel IDs carry a `dao-<slug>-` prefix server-side. When
// creating a channel from inside a group DAO, the UI prepends the slug
// so the channel lands in the right scope.
function scopedChannelId(slug: string, bare: string): string {
  if (!bare) return bare;
  if (!slug || slug === "home") return bare;
  const prefix = `dao-${slug}-`;
  return bare.startsWith(prefix) ? bare : prefix + bare;
}

function App() {
  const [agentId, setAgentId] = useState(defaultAgent);
  const [activeDao, setActiveDao] = useState<string>(defaultDao);
  const [daos, setDaos] = useState<DaoSummary[]>([]);
  const [selectedChannel, setSelectedChannel] = useState<string>("");
  const [summary, setSummary] = useState<Summary | null>(null);
  const [state, setState] = useState<DaoState | null>(null);
  const [messageBody, setMessageBody] = useState("");
  const [announcementTitle, setAnnouncementTitle] = useState("");
  const [announcementBody, setAnnouncementBody] = useState("");
  const [taskTitle, setTaskTitle] = useState("");
  const [taskDescription, setTaskDescription] = useState("");
  const [taskAssignee, setTaskAssignee] = useState("");
  const [channelName, setChannelName] = useState("");
  const [channelTopic, setChannelTopic] = useState("");
  const [notice, setNotice] = useState("Loading console state...");
  const [busy, setBusy] = useState(false);
  const [wallet, setWallet] = useState<BrowserWallet | null>(null);
  const [walletError, setWalletError] = useState<string | null>(null);
  // Week-1 Task 5: backend identifier, fetched once at mount. If it
  // never resolves the top bar shows "backend=?", which is itself a
  // signal that the user should restart the server.
  const [backendBuild, setBackendBuild] = useState<BuildId | null>(null);
  // DID bootstrap (2026-06-07): the workspace's persistent identity.
  // Drives the top-bar "Your DID: ..." line that operators copy and
  // share with peers to enable add-by-DID.
  const [nodeIdentity, setNodeIdentity] = useState<NodeIdentity | null>(null);
  const [didCopied, setDidCopied] = useState(false);
  // Week-1 Task 2 (2026-06-07): the lookupCode + lookupResult state
  // backed the now-removed "Find by code" panel. Removed entirely to
  // avoid carrying dead state through React renders.

  // Load (or generate on first run) the browser-resident Ed25519 wallet.
  // Private key stays inside IndexedDB as non-extractable CryptoKey.
  useEffect(() => {
    let cancelled = false;
    loadOrCreateWallet()
      .then((w) => { if (!cancelled) setWallet(w); })
      .catch((e: Error) => { if (!cancelled) setWalletError(e.message); });
    return () => { cancelled = true; };
  }, []);

  // Week-1 Task 5: fetch the backend build id once at mount.
  // Architect R-2 (2026-06-07): pass the caller's agentId so the
  // member-gated endpoint accepts the call.
  useEffect(() => {
    let cancelled = false;
    getBuildId(agentId || "admin")
      .then((b) => { if (!cancelled) setBackendBuild(b); })
      .catch(() => { /* leave backendBuild null - top bar shows "?" */ });
    return () => { cancelled = true; };
  }, [agentId]);

  // DID bootstrap (2026-06-07): pull this node's DID + pubkey at mount.
  useEffect(() => {
    let cancelled = false;
    getIdentity(agentId || "admin")
      .then((id) => { if (!cancelled) setNodeIdentity(id); })
      .catch(() => { /* leave null - top bar will show no DID */ });
    return () => { cancelled = true; };
  }, [agentId]);

  async function copyDidToClipboard() {
    if (!nodeIdentity?.did) return;
    try {
      await navigator.clipboard.writeText(nodeIdentity.did);
      setDidCopied(true);
      window.setTimeout(() => setDidCopied(false), 1500);
    } catch {
      // Clipboard API may be blocked on insecure origins; fall back
      // to selecting the value so user can manually Ctrl+C.
      setNotice("Copy blocked; select the DID text and Ctrl+C");
    }
  }

  const activeChannel = useMemo(
    () => state?.channels.find((channel) => channel.channel_id === selectedChannel),
    [selectedChannel, state?.channels]
  );

  async function refresh(
    nextAgent: string = agentId,
    nextChannel: string = selectedChannel,
    nextDao: string = activeDao,
  ) {
    const cleanAgent = nextAgent.trim() || "admin";
    const [summaryData, stateData] = await Promise.all([
      getSummary(cleanAgent),
      getDaoState(nextDao, cleanAgent, nextChannel),
    ]);
    setSummary(summaryData);
    setState(stateData);
    if (!nextChannel && stateData.active_channel_id) {
      setSelectedChannel(stateData.active_channel_id);
    }
    setNotice("Ready");
  }

  async function refreshDaos(pubkeyHex: string) {
    try {
      const list = await getDaos(agentId, pubkeyHex);
      setDaos(list.daos);
    } catch (e) {
      // Sidebar failures shouldn't break the main view; surface as notice.
      setNotice((e as Error).message);
    }
  }

  useEffect(() => {
    refresh().catch((error: Error) => setNotice(error.message));
    refreshDaos(wallet?.pubkeyHex ?? "");
    const id = window.setInterval(() => {
      refresh().catch((error: Error) => setNotice(error.message));
    }, 5000);
    return () => window.clearInterval(id);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [activeDao, agentId, selectedChannel, wallet?.pubkeyHex]);

  function switchDao(slug: string) {
    if (slug === activeDao) return;
    setActiveDao(slug);
    setSelectedChannel("");      // let backend pick default channel for this DAO
    window.localStorage.setItem("nth-dao-active-slug", slug);
  }

  async function run(action: () => Promise<void>, done = "Updated") {
    setBusy(true);
    setNotice("Working...");
    try {
      await action();
      await refresh();
      setNotice(done);
    } catch (error) {
      setNotice(error instanceof Error ? error.message : "Request failed");
    } finally {
      setBusy(false);
    }
  }

  function updateAgent(value: string) {
    setAgentId(value);
    window.localStorage.setItem("nth-dao-agent-id", value);
  }

  async function onJoin(event: FormEvent) {
    event.preventDefault();
    await run(async () => {
      await join(agentId.trim() || "admin");
    }, "Agent joined");
  }

  async function onCreateChannel(event: FormEvent) {
    event.preventDefault();
    const scopedId = scopedChannelId(activeDao, channelName.trim());
    await run(async () => {
      await createChannel({
        actorId: agentId,
        name: channelName,
        topic: channelTopic,
        isPrivate: false,
        channelId: scopedId,
      });
      setChannelName("");
      setChannelTopic("");
    }, "Channel created");
  }

  async function onPostMessage(event: FormEvent) {
    event.preventDefault();
    if (!messageBody.trim()) return;
    await run(async () => {
      await postMessage({ agentId, channelId: selectedChannel, body: messageBody });
      setMessageBody("");
    }, "Message posted");
  }

  async function onPostAnnouncement(event: FormEvent) {
    event.preventDefault();
    await run(async () => {
      await postAnnouncement({
        authorId: agentId,
        channelId: selectedChannel,
        title: announcementTitle,
        body: announcementBody
      });
      setAnnouncementTitle("");
      setAnnouncementBody("");
    }, "Announcement posted");
  }

  async function onCreateTask(event: FormEvent) {
    event.preventDefault();
    await run(async () => {
      await createTask({
        createdBy: agentId,
        channelId: selectedChannel,
        title: taskTitle,
        description: taskDescription,
        assigneeId: taskAssignee
      });
      setTaskTitle("");
      setTaskDescription("");
      setTaskAssignee("");
    }, "Task created");
  }

  async function onUpdateTask(taskId: string, status: TaskStatus) {
    await run(async () => {
      await updateTaskStatus({ taskId, actorId: agentId, status });
    }, "Task status updated");
  }

  // Week-1 Task 2 (2026-06-07): onLookupCode handler removed - the
  // unified ContactsPanel search now covers code lookup. See the
  // commented-out "Find by code" panel rationale in the left rail.

  return (
    <main className="shell">
      <header className="topbar">
        <div>
          <p className="eyebrow">Local-first DAO group layer</p>
          {/* 品牌正字 Nᵗʰ DAO(#8 2026-06-14):native <sup> 即上标,内联
              微调尺寸,不依赖 v2 的 .brand-th。aria-label 念回 "Nth DAO"。 */}
          <h1 aria-label="Nth DAO">
            N<sup style={{ fontSize: "0.58em", verticalAlign: "super", lineHeight: 0 }}>th</sup> DAO
          </h1>
          {/*
            Week-1 Task 5 (2026-06-07): build identifier strip. Helps
            the operator spot "I rebuilt the JS but didn't restart the
            backend" drift before debugging a phantom auth bug.
          */}
          <small className="build-id" title="backend git / bundle hash">
            backend={backendBuild?.backend_git ?? "?"} ·
            {" "}bundle={BUNDLE_HASH}
          </small>
          {/*
            DID bootstrap (2026-06-07): show this node's permanent DID
            so the operator can copy and share it with peers. The
            click-to-copy keeps the workflow one-step.
          */}
          {nodeIdentity?.did && (
            <small className="node-did" title="This NTH DAO node's permanent identifier">
              your DID:{" "}
              <code
                className="node-did-value"
                onClick={copyDidToClipboard}
                role="button"
                tabIndex={0}
              >
                {nodeIdentity.did}
              </code>
              {" "}
              <button
                type="button"
                className="node-did-copy"
                onClick={copyDidToClipboard}
                disabled={!nodeIdentity.did}
              >
                {didCopied ? "Copied ✓" : "Copy"}
              </button>
            </small>
          )}
          {nodeIdentity?.bootstrap_error && (
            <small className="node-did-error">
              identity unavailable: {nodeIdentity.bootstrap_error}
            </small>
          )}
        </div>
        <div className="status-strip" aria-live="polite">
          <Metric label="Members" value={summary?.members ?? "-"} />
          <Metric label="Channels" value={summary?.channels ?? "-"} />
          <Metric label="Tasks" value={summary?.tasks ?? "-"} />
          <Metric label="Role" value={state?.actor.role ?? "-"} />
        </div>
      </header>

      <section className="workspace">
        <aside className="left-rail">
          <form className="panel" onSubmit={onJoin}>
            <label htmlFor="agent-id">Local agent id</label>
            <div className="inline">
              <input
                id="agent-id"
                value={agentId}
                onChange={(event) => updateAgent(event.target.value)}
                spellCheck={false}
              />
              <button type="submit" disabled={busy}>Join</button>
            </div>
            <p className="hint">
              Current policy: {summary?.team.join_policy ?? "loading"}
              {/*
                R-54 (2026-06-08): label is "your handle" not "your code".
                A handle is a short, human-friendly display - NOT a
                cryptographic identifier. The tooltip directs users to
                share their DID (top bar) for verifiable identity.
                The empty-string check is intentional: when the backend
                degrades to "no crypto" (R-46), actor_code is "" and the
                hint hides entirely rather than showing a stale handle.
              */}
              {summary?.actor_code && (
                <>
                  {" / "}
                  <span title="A short display handle for this node. Not a cryptographic identifier - share your DID (top bar) for verifiable identity.">
                    your handle:{" "}
                    <code className="agent-code">{summary.actor_code}</code>
                  </span>
                </>
              )}
            </p>
          </form>

          {/*
            Week-1 Task 2 (2026-06-07): removed the duplicate "Find by
            code" panel that lived here. The same lookup is now part of
            the unified search box inside ContactsPanel (right rail) -
            having two search surfaces taught users to pick the wrong
            one. The agent-code matcher inside ``/api/agents/search``'s
            score function already finds short codes verbatim, so this
            input has no unique capability.
          */}

          {/* "My DAOs" list - one agent ↔ many DAOs. Click to switch. */}
          <section className="panel">
            <div className="panel-heading">
              <h2>My DAOs</h2>
              <span>{daos.length}</span>
            </div>
            <div className="stack dao-list">
              {daos.length === 0 && (
                <p className="empty-inline">Loading DAOs…</p>
              )}
              {daos.map((dao) => {
                const isActive = dao.slug === activeDao;
                const avatar = (dao.display_name || dao.slug).slice(0, 2).toUpperCase();
                return (
                  <button
                    key={dao.slug}
                    type="button"
                    className={`dao-item ${isActive ? "active" : ""} dao-kind-${dao.kind}`}
                    onClick={() => switchDao(dao.slug)}
                    title={dao.description || dao.display_name}
                  >
                    <span className="dao-avatar">{dao.kind === "home" ? "🏠" : avatar}</span>
                    <span className="dao-meta">
                      <span className="dao-name">{dao.display_name}</span>
                      <small>
                        {dao.kind === "home" ? "home" : `@${dao.slug}`}
                        {" / "}{dao.member_count} member{dao.member_count === 1 ? "" : "s"}
                        {dao.joined ? "" : " / not joined"}
                      </small>
                    </span>
                  </button>
                );
              })}
            </div>
          </section>

          <section className="panel">
            <div className="panel-heading">
              <h2>Channels</h2>
              <span>{state?.channels.length ?? 0}</span>
            </div>
            <div className="stack">
              {state?.channels.map((channel) => (
                <button
                  className={channel.channel_id === selectedChannel ? "channel active" : "channel"}
                  key={channel.channel_id}
                  onClick={() => {
                    setSelectedChannel(channel.channel_id);
                    refresh(agentId, channel.channel_id).catch((error: Error) => setNotice(error.message));
                  }}
                  type="button"
                >
                  <span>#{channel.name}</span>
                  <small>{channel.topic || "No topic"}</small>
                </button>
              ))}
            </div>
          </section>

          <form className="panel" onSubmit={onCreateChannel}>
            <div className="panel-heading">
              <h2>New channel</h2>
            </div>
            <input
              placeholder="Name"
              value={channelName}
              onChange={(event) => setChannelName(event.target.value)}
            />
            <input
              placeholder="Topic"
              value={channelTopic}
              onChange={(event) => setChannelTopic(event.target.value)}
            />
            <button type="submit" disabled={busy || !channelName.trim()}>Create</button>
          </form>
        </aside>

        <section className="conversation">
          <div className="conversation-head">
            <div>
              <p className="eyebrow">
                {state?.dao?.display_name ?? "Channel"}
                {state?.dao?.kind === "group" && <span className="dao-tag">@{state.dao.slug}</span>}
              </p>
              <h2>#{activeChannel?.name ?? (selectedChannel || "general")}</h2>
              {state?.dao?.kind === "group" && state?.channels.length === 0 && (
                <p className="hint">
                  This DAO has no channels yet. Use “New channel” on the left to
                  create one - it will be scoped to <code>@{state.dao.slug}</code>.
                </p>
              )}
            </div>
            <span className="notice">{notice}</span>
          </div>

          <div className="announcement-list">
            {state?.announcements.map((announcement) => (
              <article className="announcement" key={announcement.announcement_id}>
                <strong>{announcement.title}</strong>
                <p>{announcement.body}</p>
                <small>{announcement.author_id} - {shortTime(announcement.created_at)}</small>
              </article>
            ))}
          </div>

          <div className="messages">
            {state?.messages.length ? state.messages.map((message) => (
              <article className="message" key={message.message_id}>
                <div>
                  <strong>{message.sender_id}</strong>
                  <time>{shortTime(message.created_at)}</time>
                </div>
                <p>{message.body}</p>
              </article>
            )) : <p className="empty">No messages in this channel yet.</p>}
          </div>

          <form className="composer" onSubmit={onPostMessage}>
            <textarea
              placeholder="Write a message to this DAO channel"
              value={messageBody}
              onChange={(event) => setMessageBody(event.target.value)}
            />
            <button type="submit" disabled={busy || !messageBody.trim()}>Send</button>
          </form>
        </section>

        <aside className="right-rail">
          <details className="panel collapsible" open>
            <summary className="panel-heading">
              <h2>Members</h2>
              <span className="collapsible-badge">{state?.members.length ?? 0}</span>
            </summary>
            <div className="collapsible-body">
              <div className="member-list">
                {/*
                  R-64 (2026-06-08): the inline member handle gets
                  the same tooltip as the "your handle" hint above.
                  Members panel was the one place we still showed
                  the bare ``code`` without telling readers "this is
                  a display label, not a verifiable identity - use
                  DID for authentication". Without this, a member
                  who memorises another member's handle from the
                  panel might paste it into a context expecting
                  cryptographic uniqueness.
                */}
                {state?.members.map((member) => (
                  <div className="member" key={member.agent_id}>
                    <span>
                      {member.agent_id}
                      {member.code && (
                        <code
                          className="agent-code agent-code-inline"
                          title="A short display handle for this member. Not a cryptographic identifier - use the DID for verifiable identity."
                        >
                          {member.code}
                        </code>
                      )}
                    </span>
                    <small>{member.role}{member.online ? " / online" : ""}</small>
                  </div>
                ))}
              </div>
            </div>
          </details>

          <details className="panel collapsible">
            <summary className="panel-heading">
              <h2>Announcement</h2>
              <span className="collapsible-badge">post</span>
            </summary>
            <form className="collapsible-body" onSubmit={onPostAnnouncement}>
              <input
                placeholder="Title"
                value={announcementTitle}
                onChange={(event) => setAnnouncementTitle(event.target.value)}
              />
              <textarea
                placeholder="Body"
                value={announcementBody}
                onChange={(event) => setAnnouncementBody(event.target.value)}
              />
              <button type="submit" disabled={busy || !announcementTitle.trim()}>Post</button>
            </form>
          </details>

          <details className="panel collapsible">
            <summary className="panel-heading">
              <h2>Tasks</h2>
              <span className="collapsible-badge">{state?.tasks.length ?? 0}</span>
            </summary>
            <div className="collapsible-body">
              <form className="collapsible-subform" onSubmit={onCreateTask}>
                <p className="collapsible-subheading">New task</p>
                <input
                  placeholder="Title"
                  value={taskTitle}
                  onChange={(event) => setTaskTitle(event.target.value)}
                />
                <input
                  placeholder="Assignee id"
                  value={taskAssignee}
                  onChange={(event) => setTaskAssignee(event.target.value)}
                />
                <textarea
                  placeholder="Description"
                  value={taskDescription}
                  onChange={(event) => setTaskDescription(event.target.value)}
                />
                <button type="submit" disabled={busy || !taskTitle.trim()}>Create</button>
              </form>
              <div className="stack">
                {state?.tasks.map((task) => (
                  <article className="task" key={task.task_id}>
                    <strong>{task.title}</strong>
                    <small>{task.assignee_id || "unassigned"} - {task.status}</small>
                    <select
                      value={task.status}
                      onChange={(event) => onUpdateTask(task.task_id, event.target.value as TaskStatus)}
                    >
                      {taskStatuses.map((status) => (
                        <option key={status} value={status}>{status}</option>
                      ))}
                    </select>
                  </article>
                ))}
                {!state?.tasks.length && <p className="empty-inline">No tasks yet.</p>}
              </div>
            </div>
          </details>

          <details className="panel collapsible">
            <summary className="panel-heading">
              <h2>Audit</h2>
              <span className="collapsible-badge">{state?.audit.length ?? 0}</span>
            </summary>
            <div className="collapsible-body">
              <div className="audit-list">
                {state?.audit.slice().reverse().map((event) => (
                  <article className="audit" key={event.event_id}>
                    <strong>{event.event_type}</strong>
                    <span>{event.summary}</span>
                    <small>{event.actor_id} - {shortTime(event.created_at)}</small>
                  </article>
                ))}
                {!state?.audit.length && <p className="empty-inline">No audit events.</p>}
              </div>
            </div>
          </details>

          {/*
            Architect audit (2026-06-07): default-open so the friend
            discovery / contacts / groups tabs (the primary "find
            people" surface added in PR #10) are visible immediately.
            Pre-fix the panel was collapsed by default, so users opening
            the dashboard saw no UI for /api/agents/search even though
            the backend was wired up.
          */}
          <details className="panel collapsible contacts-panel-host" open>
            <summary className="panel-heading">
              <h2>Contacts / Groups</h2>
              <span className="collapsible-badge">
                {wallet ? "signed" : walletError ? "no-key" : "loading"}
              </span>
            </summary>
            <div className="collapsible-body">
              {walletError && (
                <p className="empty-inline">Wallet unavailable: {walletError}</p>
              )}
              <ContactShell
                actorId={agentId}
                actorPubkeyHex={wallet?.pubkeyHex ?? ""}
                sign={wallet?.sign}
              />
            </div>
          </details>
        </aside>
      </section>
    </main>
  );
}

function Metric({ label, value }: { label: string; value: string | number }) {
  return (
    <div className="metric">
      <span>{label}</span>
      <strong>{value}</strong>
    </div>
  );
}

function shortTime(value: string) {
  if (!value) return "";
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return value;
  return date.toLocaleString(undefined, {
    month: "short",
    day: "2-digit",
    hour: "2-digit",
    minute: "2-digit"
  });
}

export default App;
