"""
NTH DAO — Unified Web Server

Merges the read-only dashboard APIs (agents, kanban, missions, skills, ledger,
evolution) and the read-write group-chat APIs (channels, messages, tasks,
announcements, audit) into a single FastAPI application served from one port.

Start:
    python -m nth_dao.web
    # → http://localhost:8080

Environment:
    NTH_WORKSPACE   repo root (default: CWD)
    NTH_HOST        bind address  (default: 127.0.0.1)
    NTH_PORT        bind port     (default: 8080)

When a React frontend build exists at ``nth_dao/web/static/`` the server serves
it at ``/`` and falls back to ``index.html`` for SPA routing.  Without a build
the root returns a minimal JSON status page.
"""

from __future__ import annotations

import json
import os
import sys
from contextlib import asynccontextmanager
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional

from fastapi import FastAPI, HTTPException
from fastapi.responses import HTMLResponse, JSONResponse, FileResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel
import uvicorn

# ---------------------------------------------------------------------------
# Path setup — repo root so we can import nth_dao
# ---------------------------------------------------------------------------
_HERE = Path(__file__).resolve().parent
_REPO = _HERE.parent.parent
if str(_REPO) not in sys.path:
    sys.path.insert(0, str(_REPO))

import nth_dao as nth
from team_layer.blackboard import Blackboard

# ---------------------------------------------------------------------------
# Globals — lazily bootstrapped in the lifespan handler
# ---------------------------------------------------------------------------
WORKSPACE = Path(os.environ.get("NTH_WORKSPACE", _REPO)).resolve()

BB: Optional[Blackboard] = None
REGISTRY: Optional[nth.AgentRegistry] = None
MISSIONS: Optional[nth.MissionStore] = None
MEMBERSHIP: Optional[nth.MembershipManager] = None
GROUPS: Optional[nth.GroupManager] = None


# ---------------------------------------------------------------------------
# Bootstrap
# ---------------------------------------------------------------------------
def bootstrap() -> None:
    """Ensure the team exists and the general channel is created."""
    global BB, REGISTRY, MISSIONS, MEMBERSHIP, GROUPS

    # Read-only subsystems
    BB = Blackboard(WORKSPACE / "blackboard")
    REGISTRY = nth.AgentRegistry(str(WORKSPACE / "team_agents"))
    MISSIONS = nth.MissionStore(str(WORKSPACE / "missions"))

    # Read-write subsystems
    MEMBERSHIP = nth.MembershipManager(WORKSPACE)
    GROUPS = nth.GroupManager(WORKSPACE, membership=MEMBERSHIP)

    config = MEMBERSHIP.load_config()
    if not config.admin_ids and not config.member_ids:
        MEMBERSHIP.init_team(
            team_name="NTH DAO", policy="open", admin_ids=["admin"]
        )
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
    ok, reason = MEMBERSHIP.ensure_member(agent_id)      # type: ignore[union-attr]
    if not ok:
        raise HTTPException(403, reason)


def member_rows(config: nth.TeamConfig) -> list[dict]:
    return [
        {
            "agent_id": mid,
            "role": config.role_for(mid).value,
            "online": (WORKSPACE / "team_agents" / f"{mid}.json").exists(),
        }
        for mid in sorted(config.member_ids)
    ]


# ---------------------------------------------------------------------------
# Pydantic request models (read-write APIs)
# ---------------------------------------------------------------------------
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


class TaskStatusUpdate(BaseModel):
    status: str
    actor_id: str
    note: str = ""


# ---------------------------------------------------------------------------
# Lifespan
# ---------------------------------------------------------------------------
@asynccontextmanager
async def lifespan(_app: FastAPI):
    bootstrap()
    yield


# ---------------------------------------------------------------------------
# App
# ---------------------------------------------------------------------------
app = FastAPI(
    title="NTH DAO Console",
    description="Unified dashboard for NTH DAO — agents, kanban, missions, chat, tasks, audit.",
    version=nth.__version__,
    lifespan=lifespan,
)

# Static files (React build) — mounted last so API routes take priority
_STATIC = _HERE / "static"
_HAS_SPA = (_STATIC / "index.html").exists()
if _HAS_SPA:
    app.mount("/assets", StaticFiles(directory=_STATIC / "assets"), name="assets")


# ═══════════════════════════════════════════════════════════════════════════
# API — Read-only  (dashboard)
# ═══════════════════════════════════════════════════════════════════════════

@app.get("/api/team")
async def api_team():
    online = REGISTRY.list_alive()                                         # type: ignore[union-attr]
    return {
        "count": len(online),
        "agents": [
            {
                "agent_id": r.agent_id,
                "backend_id": r.backend_id,
                "status": r.status,
                "capabilities": r.capabilities,
                "groups": r.groups,
                "hostname": r.hostname,
                "current_mission": r.current_mission,
                "last_seen": r.last_seen,
                "alive": r.is_alive(),
            }
            for r in online
        ],
    }


@app.get("/api/blackboard")
async def api_blackboard():
    entries = BB.list()                                                   # type: ignore[union-attr]
    buckets: dict[str, list] = {"todo": [], "doing": [], "done": [], "blocked": [], "other": []}
    for e in entries:
        bucket = e.status if e.status in buckets else "other"
        buckets[bucket].append({
            "id": e.id,
            "scope": e.scope,
            "topic": e.topic,
            "author": e.author,
            "status": e.status,
            "content": (e.content or "")[:200],
            "updated_at": e.updated_at,
            "metadata": e.metadata,
        })
    return {"total": len(entries), "buckets": buckets}


@app.get("/api/missions")
async def api_missions():
    missions = MISSIONS.list_active()                                     # type: ignore[union-attr]
    return {
        "count": len(missions),
        "missions": [
            {
                "id": m.id,
                "title": m.title,
                "status": m.status,
                "owner": m.owner,
                "scope": m.scope,
                "priority": m.priority,
                "progress": m.progress(),
                "step_count": len(m.steps),
                "created_at": m.created_at,
            }
            for m in missions
        ],
    }


@app.get("/api/missions/{mission_id}")
async def api_mission_detail(mission_id: str):
    for m in MISSIONS.list_all():                                         # type: ignore[union-attr]
        if m.id.startswith(mission_id):
            return {
                "id": m.id,
                "title": m.title,
                "goal": m.goal,
                "status": m.status,
                "owner": m.owner,
                "scope": m.scope,
                "priority": m.priority,
                "progress": m.progress(),
                "created_at": m.created_at,
                "updated_at": m.updated_at,
                "steps": [
                    {
                        "id": s.id,
                        "description": s.description,
                        "status": s.status,
                        "assignee": s.assignee,
                        "previous_assignees": s.previous_assignees,
                        "depends_on": s.depends_on,
                        "notes": s.notes[-5:],
                        "completed_at": s.completed_at,
                    }
                    for s in m.steps
                ],
            }
    raise HTTPException(404, f"Mission {mission_id!r} not found")


@app.get("/api/ledger")
async def api_ledger(limit: int = 20):
    path = WORKSPACE / "sidechain" / "ledger.jsonl"
    if not path.exists():
        return {"count": 0, "entries": []}
    entries = []
    try:
        for line in path.read_text(encoding="utf-8").strip().split("\n")[-limit:]:
            if line.strip():
                entries.append(json.loads(line))
    except Exception as e:
        return {"count": 0, "entries": [], "error": str(e)}
    return {"count": len(entries), "entries": entries}


@app.get("/api/evolution")
async def api_evolution(limit: int = 20):
    audit_path = WORKSPACE / "sidechain" / "evolution_audit.jsonl"
    pending_dir = WORKSPACE / "sidechain" / "pending_patches"

    audit: list[dict] = []
    if audit_path.exists():
        try:
            for line in audit_path.read_text(encoding="utf-8").strip().split("\n")[-limit:]:
                if line.strip():
                    audit.append(json.loads(line))
        except Exception:
            pass

    pending: list[dict] = []
    if pending_dir.exists():
        for p in pending_dir.glob("*.json"):
            try:
                data = json.loads(p.read_text(encoding="utf-8"))
                patch = data.get("patch", {})
                pending.append({
                    "skill_id": patch.get("skill_id"),
                    "error_sig": patch.get("error_sig"),
                    "risk_level": patch.get("risk_level"),
                    "submitted_at": data.get("submitted_at"),
                })
            except Exception:
                continue

    return {"audit": audit, "pending": pending}


@app.get("/api/skills")
async def api_skills():
    skills_dir = WORKSPACE / "skills" / "registry"
    if not skills_dir.exists():
        return {"count": 0, "skills": []}
    skills = []
    for f in sorted(skills_dir.glob("*.md")):
        content = f.read_text(encoding="utf-8")
        info = {"name": f.stem, "raw_preview": content[:200]}
        for line in content.split("\n")[:10]:
            line = line.strip()
            if line.startswith("desc:"):
                info["desc"] = line[5:].strip().strip('"')
            elif line.startswith("risk:"):
                info["risk"] = line[5:].strip()
            elif line.startswith("error_sig:"):
                info["error_sig"] = line[10:].strip().strip('"')
        skills.append(info)
    return {"count": len(skills), "skills": skills}


@app.get("/api/summary")
async def api_summary():
    return {
        "agents_online": len(REGISTRY.list_alive()),                      # type: ignore[union-attr]
        "missions_active": len(MISSIONS.list_active()),                   # type: ignore[union-attr]
        "blackboard_entries": len(BB.list()),                             # type: ignore[union-attr]
        "server_time": datetime.now().isoformat(),
        "version": nth.__version__,
    }


# ═══════════════════════════════════════════════════════════════════════════
# API — Read-write  (group chat)
# ═══════════════════════════════════════════════════════════════════════════

@app.get("/api/state")
async def api_state(agent_id: str = "admin", channel_id: str = "general"):
    """Combined team state — members, channels, messages, tasks, announcements, audit."""
    ensure_open_member(agent_id)
    config = MEMBERSHIP.load_config()                                     # type: ignore[union-attr]
    return {
        "team": config.to_dict(),
        "role": config.role_for(agent_id).value,
        "members": member_rows(config),
        "channels": [c.to_dict() for c in GROUPS.list_channels(actor_id=agent_id)],   # type: ignore[union-attr]
        "messages": [
            m.to_dict()
            for m in GROUPS.list_messages(channel_id, actor_id=agent_id, limit=100)   # type: ignore[union-attr]
        ],
        "announcements": [a.to_dict() for a in GROUPS.list_announcements(channel_id)],# type: ignore[union-attr]
        "tasks": [t.to_dict() for t in GROUPS.list_tasks()],                           # type: ignore[union-attr]
        "audit": [e.to_dict() for e in GROUPS.list_audit_events(limit=20)],            # type: ignore[union-attr]
    }


@app.post("/api/join")
async def api_join(payload: JoinIn):
    ensure_open_member(payload.agent_id)
    channel = GROUPS.get_channel(payload.channel_id)                      # type: ignore[union-attr]
    if channel and payload.agent_id not in channel.member_ids:
        channel.member_ids.append(payload.agent_id)
        GROUPS._write_json(GROUPS._channel_path(channel.channel_id), channel.to_dict())  # type: ignore[union-attr]
    return {"ok": True, "agent_id": payload.agent_id, "channel_id": payload.channel_id}


@app.post("/api/messages")
async def api_post_message(payload: MessageIn):
    ensure_open_member(payload.agent_id)
    msg = GROUPS.post_message(                                            # type: ignore[union-attr]
        payload.channel_id, sender_id=payload.agent_id, body=payload.body
    )
    return msg.to_dict()


@app.post("/api/announcements")
async def api_post_announcement(payload: AnnouncementIn):
    ann = GROUPS.post_announcement(                                       # type: ignore[union-attr]
        payload.title, payload.body,
        author_id=payload.author_id, channel_id=payload.channel_id,
    )
    return ann.to_dict()


@app.post("/api/tasks")
async def api_create_task(payload: TaskIn):
    ensure_open_member(payload.created_by)
    if payload.assignee_id:
        ensure_open_member(payload.assignee_id)
    task = GROUPS.create_task(                                            # type: ignore[union-attr]
        payload.title, created_by=payload.created_by,
        description=payload.description, assignee_id=payload.assignee_id,
        channel_id=payload.channel_id,
    )
    return task.to_dict()


@app.patch("/api/tasks/{task_id}")
async def api_update_task(task_id: str, payload: TaskStatusUpdate):
    task = GROUPS.update_task_status(                                     # type: ignore[union-attr]
        task_id, payload.status, actor_id=payload.actor_id, note=payload.note
    )
    return task.to_dict()


# ═══════════════════════════════════════════════════════════════════════════
# Root  — SPA fallback if React built, else JSON status
# ═══════════════════════════════════════════════════════════════════════════

@app.get("/", response_class=HTMLResponse)
async def index():
    if _HAS_SPA:
        return FileResponse(_STATIC / "index.html")
    return HTMLResponse(
        "<html><body><h1>NTH DAO Console</h1>"
        "<p>API server running. "
        "Run <code>cd frontend && npm run dev</code> for the React UI.</p>"
        "</body></html>"
    )


# SPA fallback — serve index.html for any non-API route (client-side routing)
@app.get("/{path:path}")
async def spa_fallback(path: str):
    if path.startswith("api/"):
        raise HTTPException(404)
    if _HAS_SPA:
        candidate = _STATIC / path
        if candidate.is_file():
            return FileResponse(candidate)
        return FileResponse(_STATIC / "index.html")
    raise HTTPException(404)


# ═══════════════════════════════════════════════════════════════════════════
# Entrypoint
# ═══════════════════════════════════════════════════════════════════════════

def main() -> None:
    host = os.environ.get("NTH_HOST", "127.0.0.1")
    port = int(os.environ.get("NTH_PORT", "8080"))
    print(f"⚡ NTH DAO Console  v{nth.__version__}")
    print(f"   workspace : {WORKSPACE}")
    print(f"   URL       : http://{host}:{port}")
    print(f"   API docs  : http://{host}:{port}/docs")
    if _HAS_SPA:
        print(f"   React UI  : bundled ✓")
    else:
        print(f"   React UI  : not bundled — see frontend/")
    print("   Ctrl+C to stop")
    uvicorn.run(app, host=host, port=port, log_level="info")


if __name__ == "__main__":
    main()
