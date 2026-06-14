"""Local group chat server for NTH DAO.

⚠️ DEPRECATED (2026-06-14): group chat is now a first-class view in the v2
console — the **Channels** tab, served by the main hub at ``/v2`` and backed
by ``/api/v2/channels`` (with built-in agent listen-and-reply). That path
shares the v2 dark theme, i18n, and agent supervisor; this standalone 8765
server does NOT (no language switch, no agent auto-reply). It is kept only as
a minimal self-contained demo of the GroupManager API. For real use, run the
hub (``python -m nth_dao.web``) and open the Channels tab.

Run (demo only):
    python examples/group_chat_server.py
"""

from __future__ import annotations

import os
import sys
from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import FastAPI, HTTPException
from fastapi.responses import HTMLResponse
from pydantic import BaseModel
import uvicorn

REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO))

import nth_dao as nth


WORKSPACE = Path(os.environ.get("NTH_WORKSPACE", REPO)).resolve()
MEMBERSHIP = nth.MembershipManager(WORKSPACE)
GROUPS = nth.GroupManager(WORKSPACE, membership=MEMBERSHIP)


class MessageIn(BaseModel):
    agent_id: str
    body: str
    channel_id: str = "general"


class JoinIn(BaseModel):
    agent_id: str
    channel_id: str = "general"


class AnnouncementIn(BaseModel):
    author_id: str
    title: str
    body: str
    channel_id: str = "general"


class TaskIn(BaseModel):
    created_by: str
    title: str
    description: str = ""
    assignee_id: str = ""
    channel_id: str = "general"


def bootstrap() -> None:
    config = MEMBERSHIP.load_config()
    if not config.admin_ids and not config.member_ids:
        MEMBERSHIP.init_team(team_name="NTH DAO", policy="open", admin_ids=["admin"])
    elif not config.admin_ids:
        if "admin" not in config.member_ids:
            config.member_ids.append("admin")
        config.admin_ids.append("admin")
        config.roles["admin"] = nth.TeamRole.OWNER.value
        MEMBERSHIP.save_config(config)
    elif config.team_name in {"Unnamed Team", "NTH DAO"}:
        config.team_name = "NTH DAO"
        MEMBERSHIP.save_config(config)
    if GROUPS.get_channel("general") is None:
        GROUPS.create_channel("general", created_by="admin", topic="Team chat")


def ensure_open_member(agent_id: str) -> None:
    if not agent_id:
        raise HTTPException(400, "agent_id is required")
    ok, reason = MEMBERSHIP.ensure_member(agent_id)
    if not ok:
        raise HTTPException(403, reason)


def member_rows(config: nth.TeamConfig) -> list[dict]:
    return [
        {
            "agent_id": member_id,
            "role": config.role_for(member_id).value,
            "online": (WORKSPACE / "team_agents" / f"{member_id}.json").exists(),
        }
        for member_id in sorted(config.member_ids)
    ]


@asynccontextmanager
async def lifespan(_app: FastAPI):
    bootstrap()
    yield


app = FastAPI(title="NTH DAO Group Chat", version=nth.__version__, lifespan=lifespan)


@app.get("/", response_class=HTMLResponse)
async def index():
    return INDEX_HTML


@app.get("/api/state")
async def api_state(agent_id: str = "admin", channel_id: str = "general"):
    ensure_open_member(agent_id)
    config = MEMBERSHIP.load_config()
    return {
        "team": config.to_dict(),
        "role": config.role_for(agent_id).value,
        "members": member_rows(config),
        "channels": [c.to_dict() for c in GROUPS.list_channels(actor_id=agent_id)],
        "messages": [
            m.to_dict()
            for m in GROUPS.list_messages(channel_id, actor_id=agent_id, limit=100)
        ],
        "announcements": [a.to_dict() for a in GROUPS.list_announcements(channel_id)],
        "tasks": [t.to_dict() for t in GROUPS.list_tasks()],
        "audit": [e.to_dict() for e in GROUPS.list_audit_events(limit=20)],
    }


@app.post("/api/join")
async def api_join(payload: JoinIn):
    ensure_open_member(payload.agent_id)
    channel = GROUPS.get_channel(payload.channel_id)
    if channel and payload.agent_id not in channel.member_ids:
        GROUPS.add_channel_member(
            channel_id=payload.channel_id,
            agent_id=payload.agent_id,
            added_by=payload.agent_id,
        )
    return {"ok": True, "agent_id": payload.agent_id, "channel_id": payload.channel_id}


@app.post("/api/messages")
async def api_post_message(payload: MessageIn):
    ensure_open_member(payload.agent_id)
    msg = GROUPS.post_message(
        payload.channel_id,
        sender_id=payload.agent_id,
        body=payload.body,
    )
    return msg.to_dict()


@app.post("/api/announcements")
async def api_post_announcement(payload: AnnouncementIn):
    announcement = GROUPS.post_announcement(
        payload.title,
        payload.body,
        author_id=payload.author_id,
        channel_id=payload.channel_id,
    )
    return announcement.to_dict()


@app.post("/api/tasks")
async def api_create_task(payload: TaskIn):
    ensure_open_member(payload.created_by)
    if payload.assignee_id:
        ensure_open_member(payload.assignee_id)
    task = GROUPS.create_task(
        payload.title,
        created_by=payload.created_by,
        description=payload.description,
        assignee_id=payload.assignee_id,
        channel_id=payload.channel_id,
    )
    return task.to_dict()


INDEX_HTML = """<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>NTH DAO Chat</title>
<style>
:root{--bg:#f7f8fb;--line:#d9dee7;--ink:#20242c;--muted:#667085;--panel:#fff;--accent:#2563eb;--soft:#e8f0ff;--good:#0f766e;--warn:#b45309}
*{box-sizing:border-box} body{margin:0;font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",sans-serif;color:var(--ink);background:var(--bg)}
header{height:56px;display:flex;align-items:center;gap:14px;padding:0 18px;border-bottom:1px solid var(--line);background:var(--panel)}
h1{font-size:17px;margin:0;font-weight:650} main{display:grid;grid-template-columns:260px minmax(0,1fr)300px;min-height:calc(100vh - 56px)}
aside,section{border-right:1px solid var(--line);background:var(--panel)} .left,.right{padding:14px}.chat{display:grid;grid-template-rows:auto 1fr auto;min-width:0;background:#fbfcff}
.bar{padding:12px 16px;border-bottom:1px solid var(--line);display:flex;align-items:center;justify-content:space-between;background:var(--panel)}
.messages{padding:16px;overflow-y:auto;min-height:360px}.message{max-width:760px;margin:0 0 12px;padding:10px 12px;border:1px solid var(--line);border-radius:8px;background:var(--panel)}
.meta{color:var(--muted);font-size:12px;margin-bottom:5px}.composer{display:grid;grid-template-columns:minmax(0,1fr)auto;gap:8px;padding:12px 16px;border-top:1px solid var(--line);background:var(--panel)}
input,textarea,button{font:inherit;border:1px solid var(--line);border-radius:6px;background:#fff} input,textarea{padding:8px 10px;width:100%} textarea{min-height:72px;resize:vertical}
button{padding:8px 12px;background:var(--accent);border-color:var(--accent);color:#fff;cursor:pointer} button.secondary{background:#fff;color:var(--accent)}
.stack{display:grid;gap:10px}.item{padding:8px 10px;border:1px solid var(--line);border-radius:8px;background:#fff}.channel.active{background:var(--soft);border-color:#b7cdfd}
.small{font-size:12px;color:var(--muted)}.role{color:var(--good);font-size:12px}.mono{font-family:ui-monospace,SFMono-Regular,Consolas,monospace}.pill{display:inline-flex;padding:2px 7px;border:1px solid var(--line);border-radius:999px;font-size:12px;color:var(--muted)}
.member-row{display:flex;align-items:center;justify-content:space-between;gap:8px}.dot{width:8px;height:8px;border-radius:99px;display:inline-block;background:#cbd5e1}.dot.online{background:var(--good)}
.task-open{color:var(--warn)} @media(max-width:900px){main{grid-template-columns:1fr}.right{display:none}aside{border-right:0;border-bottom:1px solid var(--line)}}
</style>
</head>
<body>
<header>
  <h1>NTH DAO Chat</h1>
  <input id="agent" value="admin" style="max-width:220px" />
  <span id="role" class="role"></span>
  <button class="secondary" onclick="refresh()">Refresh</button>
</header>
<main>
  <aside class="left"><div class="stack">
    <strong>Team</strong>
    <div class="item"><div class="small">group id</div><div id="team-id" class="mono"></div><div id="join-policy" class="small"></div></div>
    <input id="join-agent" placeholder="agent_id to join" />
    <button onclick="joinTeam()">Join / Switch</button>
    <input id="search" placeholder="search members, channels, messages" oninput="renderSearch()" />
    <div id="search-results"></div>
    <strong>Members</strong><div id="members"></div>
    <strong>Channels</strong><div id="channels"></div>
    <div class="small">Local-first workspace. Files can be synced by Git.</div>
  </div></aside>
  <section class="chat">
    <div class="bar"><strong id="title"># general</strong><span id="status" class="small"></span></div>
    <div id="messages" class="messages"></div>
    <div class="composer"><textarea id="body" placeholder="Type a group message"></textarea><button onclick="sendMessage()">Send</button></div>
  </section>
  <aside class="right"><div class="stack">
    <strong>Announcements</strong>
    <input id="ann-title" placeholder="title" /><textarea id="ann-body" placeholder="announcement"></textarea><button onclick="postAnnouncement()">Post announcement</button><div id="announcements"></div>
    <strong>Tasks</strong>
    <input id="task-title" placeholder="task title" /><input id="task-assignee" placeholder="assignee agent_id" /><textarea id="task-desc" placeholder="task description"></textarea><button onclick="createTask()">Create task</button><div id="tasks"></div>
  </div></aside>
</main>
<script>
let channel="general"; let currentState=null;
const $=(id)=>document.getElementById(id);
const esc=(s)=>String(s??"").replace(/[&<>"]/g,c=>({"&":"&amp;","<":"&lt;",">":"&gt;","\\"":"&quot;"}[c]));
const when=(s)=>s?new Date(s).toLocaleString():"";
async function json(url,opts={}){const res=await fetch(url,opts);if(!res.ok)throw new Error(await res.text());return res.json();}
async function refresh(){
  try{
    const agent=$("agent").value.trim()||"admin";
    const state=await json(`/api/state?agent_id=${encodeURIComponent(agent)}&channel_id=${encodeURIComponent(channel)}`);
    currentState=state; $("role").textContent=`role: ${state.role}`; $("team-id").textContent=state.team.team_id; $("join-policy").textContent=`join: ${state.team.join_policy}`; $("status").textContent=`${state.messages.length} messages`; $("title").textContent=`# ${channel}`;
    $("channels").innerHTML=state.channels.map(c=>`<div class="item channel ${c.channel_id===channel?"active":""}" onclick="channel='${esc(c.channel_id)}';refresh()"><strong>${esc(c.name)}</strong><div class="small">${esc(c.topic||c.channel_id)}</div></div>`).join("");
    $("members").innerHTML=state.members.map(m=>`<div class="item member-row"><span><span class="dot ${m.online?"online":""}"></span> <span class="mono">${esc(m.agent_id)}</span></span><span class="pill">${esc(m.role)}</span></div>`).join("");
    $("messages").innerHTML=state.messages.map(m=>`<div class="message"><div class="meta">${esc(m.sender_id)} - ${when(m.created_at)}</div><div>${esc(m.body).replace(/\\n/g,"<br>")}</div></div>`).join("")||'<div class="small">No messages yet.</div>'; $("messages").scrollTop=$("messages").scrollHeight;
    $("announcements").innerHTML=state.announcements.map(a=>`<div class="item"><strong>${esc(a.title)}</strong><div>${esc(a.body)}</div><div class="small">${esc(a.author_id)} - ${when(a.created_at)}</div></div>`).join("")||'<div class="small">No announcements.</div>';
    $("tasks").innerHTML=state.tasks.map(t=>`<div class="item"><strong>${esc(t.title)}</strong><div class="small">${esc(t.assignee_id||"unassigned")} - <span class="task-open">${esc(t.status)}</span></div></div>`).join("")||'<div class="small">No tasks.</div>';
    renderSearch();
  }catch(e){$("status").textContent=e.message;}
}
async function joinTeam(){const next=$("join-agent").value.trim();if(!next)return;await json("/api/join",{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify({agent_id:next,channel_id:channel})});$("agent").value=next;$("join-agent").value="";refresh();}
function renderSearch(){if(!currentState)return;const q=$("search").value.trim().toLowerCase();if(!q){$("search-results").innerHTML="";return;}const hits=[];currentState.members.forEach(m=>{if(`${m.agent_id} ${m.role}`.toLowerCase().includes(q))hits.push(`<div class="item"><strong>member</strong><div class="small mono">${esc(m.agent_id)} / ${esc(m.role)}</div></div>`)});currentState.channels.forEach(c=>{if(`${c.channel_id} ${c.name} ${c.topic}`.toLowerCase().includes(q))hits.push(`<div class="item" onclick="channel='${esc(c.channel_id)}';refresh()"><strong>channel</strong><div class="small mono">${esc(c.channel_id)}</div></div>`)});currentState.messages.forEach(m=>{if(`${m.sender_id} ${m.body}`.toLowerCase().includes(q))hits.push(`<div class="item"><strong>message</strong><div class="small">${esc(m.sender_id)}: ${esc(m.body).slice(0,80)}</div></div>`)});$("search-results").innerHTML=hits.slice(0,8).join("")||'<div class="small">no matches</div>';}
async function sendMessage(){const body=$("body").value.trim();if(!body)return;await json("/api/messages",{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify({agent_id:$("agent").value.trim()||"admin",channel_id:channel,body})});$("body").value="";refresh();}
async function postAnnouncement(){await json("/api/announcements",{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify({author_id:$("agent").value.trim()||"admin",channel_id:channel,title:$("ann-title").value.trim(),body:$("ann-body").value.trim()})});$("ann-title").value="";$("ann-body").value="";refresh();}
async function createTask(){await json("/api/tasks",{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify({created_by:$("agent").value.trim()||"admin",channel_id:channel,title:$("task-title").value.trim(),assignee_id:$("task-assignee").value.trim(),description:$("task-desc").value.trim()})});$("task-title").value="";$("task-assignee").value="";$("task-desc").value="";refresh();}
$("body").addEventListener("keydown",(e)=>{if(e.key==="Enter"&&(e.ctrlKey||e.metaKey))sendMessage();});
refresh(); setInterval(refresh,3000);
</script>
</body>
</html>
"""


def main() -> None:
    host = os.environ.get("NTH_CHAT_HOST", "127.0.0.1")
    port = int(os.environ.get("NTH_CHAT_PORT", "8765"))
    print("⚠️  DEPRECATED demo. Group chat is now the v2 console 'Channels'")
    print("    tab (python -m nth_dao.web → open /v2). This 8765 server has")
    print("    no language switch and no agent auto-reply.")
    print(f"NTH DAO group chat (demo): http://{host}:{port}")
    print(f"workspace: {WORKSPACE}")
    uvicorn.run(app, host=host, port=port, log_level="info")


if __name__ == "__main__":
    main()
