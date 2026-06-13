"""NTH DAO Telegram Bot - expose the NTH DAO runtime through Telegram.

Run:
    python nth_telegram_bot.py

Requires in ``~/.hermes/.env``:
    TELEGRAM_BOT_TOKEN=...
    TELEGRAM_ALLOWED_USERS=<comma-separated Telegram user IDs>
    DEEPSEEK_API_KEY=...

Commands:
    /start              register the user + greet
    /team               list discoverable agents on the workspace
    /kanban             render Blackboard as a kanban summary
    /mission_new <title> | <step1> ; <step2>
                        create a Mission (title | semicolon-separated steps)
    /mission_list       list active missions
    /evolve             trigger EvoLoop.run_once()
    /ledger             tail the last ~10 ledger entries
    <free text>         routed to DeepSeek with the agent's ledger context

Notes:
- Workspace is the repo root; the bot attaches via ``nth_dao.attach()``
  as agent_id ``telegram-bot`` and writes to the standard NTH DAO paths.
- DeepSeek is reached via the openai SDK with a custom base_url.
- Module import is side-effect-free: env validation and LLM/runtime
  initialisation are *lazy*. `_validate_env()` is called from `main()`
  before the bot starts; `get_llm()` and `get_runtime()` are called by
  individual handlers on first use. This makes the module safe to
  `import` from tests / linters without env vars set.

Original lazy-init pattern contributed by @andy1868 in PR #7.
"""

from __future__ import annotations

import asyncio
import json
import logging
import os
import sys
from functools import wraps
from html import escape as html_escape
from pathlib import Path

# Windows UTF-8
if sys.platform == "win32":
    try:
        sys.stdout.reconfigure(encoding="utf-8")
        sys.stderr.reconfigure(encoding="utf-8")
    except AttributeError:
        pass

# 1.  ~/.hermes/.env
def _load_dotenv(path: Path):
    if not path.exists():
        return
    for line in path.read_text(encoding="utf-8").split("\n"):
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        k, _, v = line.partition("=")
        os.environ.setdefault(k.strip(), v.strip())

_load_dotenv(Path.home() / ".hermes" / ".env")

# 2. Read env into module-level constants; do NOT exit on missing values -
#    that breaks pytest collection and any tooling that just imports this
#    module. Validation is deferred to `_validate_env()` (called by main).
TOKEN = os.environ.get("TELEGRAM_BOT_TOKEN")
DEEPSEEK_KEY = os.environ.get("DEEPSEEK_API_KEY")


def _allowed_users() -> set[str]:
    return {
        u.strip()
        for u in os.environ.get("TELEGRAM_ALLOWED_USERS", "").split(",")
        if u.strip()
    }


def _open_access_enabled() -> bool:
    return os.environ.get("TELEGRAM_ALLOW_OPEN", "").strip().lower() in {"1", "true", "yes"}


def _validate_env() -> None:
    """Raise RuntimeError if required env vars are missing.

    Called from `main()`; safe to skip during `import` so tests and
    static analysis don't need the secrets present.
    """
    missing = []
    if not os.environ.get("TELEGRAM_BOT_TOKEN"):
        missing.append("TELEGRAM_BOT_TOKEN")
    if not os.environ.get("DEEPSEEK_API_KEY"):
        missing.append("DEEPSEEK_API_KEY")
    if not _allowed_users() and not _open_access_enabled():
        missing.append("TELEGRAM_ALLOWED_USERS (or TELEGRAM_ALLOW_OPEN=1)")
    if missing:
        raise RuntimeError(
            f"Missing required env vars: {', '.join(missing)}. "
            "Set them in ~/.hermes/.env (see this module's docstring)."
        )


# 3.  nth_dao
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
import nth_dao as nth
from nth_dao import render_kanban           # facade re-export
from nth_dao.orchestration import StepStatus

logging.basicConfig(
    format="%(asctime)s %(levelname)s %(name)s: %(message)s",
    level=logging.INFO,
)
logger = logging.getLogger("nth-bot")
#  telegram  verbose
logging.getLogger("httpx").setLevel(logging.WARNING)
logging.getLogger("telegram").setLevel(logging.WARNING)


def h(value) -> str:
    return html_escape(str(value), quote=True)


def truncate(value: str, limit: int) -> str:
    return value if len(value) <= limit else value[:limit] + "\n... (truncated)"

#
# NTH DAO
#

REPO = Path(__file__).resolve().parent.parent

# Lazy runtime + LLM singletons. We do NOT touch network / file-system on
# import - handlers call get_runtime() / get_llm() on first use.
_TEAM = None
_LLM = None


def get_runtime():
    """Attach to NTH DAO on first call; return the cached session."""
    global _TEAM
    if _TEAM is None:
        _TEAM = nth.attach(
            agent_id="telegram-bot",
            backend=None,                          # routed to DeepSeek below
            capabilities=["chat", "telegram", "qa"],
            groups=["bots"],
            workspace=REPO,
            start_heartbeat=True,
        )
        logger.info("NTH DAO attached: %s on %s", _TEAM.agent_id, _TEAM.workspace)
    return _TEAM


def get_llm() -> OpenAI:
    """Return the shared DeepSeek client, initialising it lazily."""
    global _LLM
    if _LLM is None:
        key = os.environ.get("DEEPSEEK_API_KEY")
        if not key:
            raise RuntimeError(
                "DEEPSEEK_API_KEY is not set; cannot reach DeepSeek. "
                "Add it to ~/.hermes/.env."
            )
        try:
            from openai import OpenAI
        except ImportError as exc:
            raise RuntimeError(
                "The openai package is required for DeepSeek access. "
                "Install it before running this bot."
            ) from exc
        _LLM = OpenAI(api_key=key, base_url="https://api.deepseek.com/v1")
    return _LLM


# Legacy name kept for backwards compatibility with the rest of this file
# (TEAM was referenced unconditionally before the lazy refactor). Modules
# that import this script directly should prefer get_runtime() / get_llm().
class _RuntimeProxy:
    """Tiny proxy so `TEAM.foo` lazily forwards to the real runtime."""
    def __getattr__(self, name):
        return getattr(get_runtime(), name)


TEAM = _RuntimeProxy()

#
#
#

def authorized_only(handler):
    """Allow only configured Telegram user IDs unless open access is explicit."""
    @wraps(handler)
    async def wrapper(update: Update, context: ContextTypes.DEFAULT_TYPE):
        uid = str(update.effective_user.id) if update.effective_user else ""
        allowed = _allowed_users()
        if not allowed and not _open_access_enabled():
            logger.warning("DENY user_id=%s (allowlist is not configured)", uid)
            await update.message.reply_text(
                "This bot is locked. Ask the administrator to configure TELEGRAM_ALLOWED_USERS."
            )
            return
        if allowed and uid not in allowed:
            logger.warning(f"DENY user_id={uid} (not in allowlist)")
            await update.message.reply_text(
                f"Unauthorized user_id={uid}. Ask the administrator to add you to TELEGRAM_ALLOWED_USERS."
            )
            return
        try:
            user_name = update.effective_user.first_name if update.effective_user else "?"
            msg = update.message.text or ""
            handler_name = handler.__name__.replace("cmd_", "/")
            logger.info(f"CMD {handler_name:20s} from {user_name:10s} args=`{msg[:80]}`")
        except Exception:
            pass
        try:
            return await handler(update, context)
        except Exception as e:
            logger.exception(f"Handler {handler.__name__} failed: {e}")
            try:
                await update.message.reply_text(
                    f" Internal error in {handler.__name__}: {type(e).__name__}: {str(e)[:200]}"
                )
            except Exception:
                pass
    return wrapper

#
#  Handlers
#

@authorized_only
async def cmd_start(update: Update, _ctx: ContextTypes.DEFAULT_TYPE):
    await update.message.reply_text(
        "NTH DAO Bot is online.\n\n"
        "/team - list online agents\n"
        "/kanban - show the blackboard\n"
        "/mission_new <title> | <step1> ; <step2> ; ...\n"
        "Example: /mission_new ship payments | design api ; build ui ; e2e tests\n"
        "/mission_list - list active missions\n"
        "/evolve - run EvoLoop once\n"
        "/ledger - show recent ledger entries\n\n"
        "Plain text messages are routed to DeepSeek with NTH DAO context."
    )

@authorized_only
async def cmd_team(update: Update, _ctx: ContextTypes.DEFAULT_TYPE):
    online = TEAM.registry.list_alive()
    if not online:
        await update.message.reply_text("(no agents online)")
        return
    lines = ["Online agents:\n"]
    for r in online:
        caps = ",".join(r.capabilities[:3]) or "-"
        lines.append(f"{r.agent_id} [{r.status}] caps=[{caps}] on {r.hostname}")
    await update.message.reply_text("\n".join(lines))

@authorized_only
async def cmd_kanban(update: Update, _ctx: ContextTypes.DEFAULT_TYPE):
    entries = TEAM.blackboard.list()
    if not entries:
        await update.message.reply_text("The blackboard is empty. Create work with /mission_new.")
        return
    kanban_text = render_kanban(entries, width=22)
    # Telegram  4096 + Markdown code block
    if len(kanban_text) > 3800:
        kanban_text = kanban_text[:3800] + "\n... (truncated)"
    await update.message.reply_text(f"<pre>{h(kanban_text)}</pre>", parse_mode="HTML")

@authorized_only
async def cmd_mission_new(update: Update, ctx: ContextTypes.DEFAULT_TYPE):
    args = " ".join(ctx.args) if ctx.args else ""
    if "|" not in args:
        await update.message.reply_text(
            "Usage: /mission_new <title> | <step1> ; <step2> ; ...\n"
            "Example: /mission_new ship payments | design api ; build ui ; e2e tests"
        )
        return
    title, _, steps_part = args.partition("|")
    title = title.strip()
    steps_descs = [s.strip() for s in steps_part.split(";") if s.strip()]
    if not steps_descs:
        await update.message.reply_text("Add at least one step after the | separator.")
        return
    steps = [
        {"id": f"step-{i+1}", "description": d, "depends_on": [f"step-{i}"] if i > 0 else []}
        for i, d in enumerate(steps_descs)
    ]
    mission = TEAM.start_mission(title=title, goal=title, steps=steps)
    short_id = mission.id[:8]
    step_examples = "\n".join([
        f"  /complete_step {short_id} {s['id']} "
        for s in steps[:2]
    ])
    await update.message.reply_text(
        f"<b>Mission created</b>\n\n"
        f"id:    <code>{h(mission.id)}</code>\n"
        f"title: {h(mission.title)}\n"
        f"steps: {len(steps)} ({', '.join(s['id'] for s in steps)})\n\n"
        f"<b>Next commands</b> using short id <code>{h(short_id)}</code>:\n"
        f"  /mission_take\n"
        f"  /mission_show {short_id}\n"
        f"{h(step_examples)}",
        parse_mode="HTML",
    )

@authorized_only
async def cmd_mission_list(update: Update, _ctx: ContextTypes.DEFAULT_TYPE):
    missions = TEAM.mission_store.list_active()
    if not missions:
        await update.message.reply_text("(no active missions)")
        return
    lines = ["Active missions:\n"]
    for m in missions[:10]:
        p = m.progress()
        lines.append(
            f"{m.id} {m.title}\n"
            f"  status: {m.status} | {p['done']}/{p['total']} done ({p['percent']}%)"
        )
    await update.message.reply_text("\n".join(lines))

@authorized_only
async def cmd_evolve(update: Update, _ctx: ContextTypes.DEFAULT_TYPE):
    from team_layer.evolution import EvoLoop
    ledger = TEAM.memory.providers["LedgerProvider"]
    loop = EvoLoop(ledger=ledger)
    results = loop.run_once()
    if not results:
        await update.message.reply_text("No error signatures crossed the ROI threshold yet.")
        return
    lines = [f"Evolved {len(results)} signature(s):\n"]
    for r in results:
        sig = r.decision.error_sig
        gate = r.gate.action.value if r.gate else "no-gate"
        lines.append(f"{sig} -> {gate}")
    await update.message.reply_text("\n".join(lines))

@authorized_only
async def cmd_ledger(update: Update, _ctx: ContextTypes.DEFAULT_TYPE):
    # flush in-memory buffer + read recent
    ledger = TEAM.memory.providers["LedgerProvider"]
    entries = []
    if hasattr(ledger, "buffer") and ledger.buffer:
        entries.extend(ledger.buffer[-10:])
    ledger_path = REPO / "sidechain" / "ledger.jsonl"
    if ledger_path.exists():
        for line in ledger_path.read_text(encoding="utf-8").strip().split("\n")[-10:]:
            if line.strip():
                try:
                    entries.append(json.loads(line))
                except Exception:
                    continue
    if not entries:
        await update.message.reply_text("No ledger entries yet.")
        return
    lines = ["Recent ledger entries:\n"]
    for e in entries[-10:]:
        sig = e.get("error_sig") or "ok"
        lines.append(f" [{sig[:20]}] cost={e.get('token_cost',0)}t action={e.get('action_type','?')[:25]}")
    await update.message.reply_text("\n".join(lines))


#
# Mission PR 8 MissionRunner  Telegram
#

def _resolve_mission(mission_id_prefix: str):
    """Resolve a mission by id prefix."""
    for m in TEAM.mission_store.list_active():
        if m.id.startswith(mission_id_prefix):
            return m
    return None


@authorized_only
async def cmd_mission_show(update: Update, ctx: ContextTypes.DEFAULT_TYPE):
    """Show mission details and recent step notes."""
    if not ctx.args:
        await update.message.reply_text("Usage: /mission_show <mission_id_prefix>")
        return
    m = _resolve_mission(ctx.args[0])
    if not m:
        await update.message.reply_text(f"Mission not found: {ctx.args[0]}")
        return
    p = m.progress()
    lines = [
        f"<b>{h(m.title)}</b> <code>{h(m.id)}</code>",
        f"status: {h(m.status)} | {p['done']}/{p['total']} done ({p['percent']}%)",
        f"owner: {h(m.owner)}",
        f"scope: {h(m.scope)}",
        "",
        "*Steps:*",
    ]
    for s in m.steps:
        assignee = s.assignee or ""
        deps = f" deps={s.depends_on}" if s.depends_on else ""
        lines.append(f"<code>{h(s.id)}</code> [{h(s.status)}] {h(s.description[:60])} by <code>{h(assignee)}</code>{h(deps)}")
        for note in s.notes[-2:]:
            lines.append(f"    {h(note[:100])}")
    await update.message.reply_text("\n".join(lines), parse_mode="HTML")


@authorized_only
async def cmd_mission_take(update: Update, _ctx: ContextTypes.DEFAULT_TYPE):
    """Claim the next actionable step matching this bot's capabilities."""
    found = TEAM.runner.find_work()
    if not found:
        await update.message.reply_text(
            "No actionable step matches capabilities=" + str(TEAM.capabilities)
        )
        return
    m, s = found
    TEAM.runner.claim(m.id, s.id)
    TEAM.registry.update_status(status="busy", current_mission=m.id)
    await update.message.reply_text(
        f"Claimed step:\n"
        f"mission: {m.id} {m.title}\n"
        f"step:    {s.id} {s.description}\n"
        f"/complete_step {m.id[:8]} {s.id}",
    )


@authorized_only
async def cmd_complete_step(update: Update, ctx: ContextTypes.DEFAULT_TYPE):
    """Complete a mission step."""
    if len(ctx.args) < 2:
        await update.message.reply_text("Usage: /complete_step <mission_id_prefix> <step_id> [note]")
        return
    m = _resolve_mission(ctx.args[0])
    if not m:
        await update.message.reply_text(f"Mission not found: {ctx.args[0]}")
        return
    step_id = ctx.args[1]
    note = " ".join(ctx.args[2:]) if len(ctx.args) > 2 else "completed via telegram"
    outcome = TEAM.runner.complete(m.id, step_id, note=note)
    if not outcome.success:
        await update.message.reply_text(f"Failed: step {step_id} not found")
        return
    TEAM.registry.update_status(status="idle")
    fresh = TEAM.mission_store.get(m.id)
    extra = "\nMission is now complete." if fresh and fresh.is_finished() else ""
    await update.message.reply_text(
        f"Step {step_id} marked DONE in mission {m.id[:8]}\n"
        f"note: {note}{extra}",
    )


@authorized_only
async def cmd_fail_step(update: Update, ctx: ContextTypes.DEFAULT_TYPE):
    """Mark a mission step as failed."""
    if len(ctx.args) < 3:
        await update.message.reply_text("Usage: /fail_step <mission_id_prefix> <step_id> <reason>")
        return
    m = _resolve_mission(ctx.args[0])
    if not m:
        await update.message.reply_text(f"Mission not found: {ctx.args[0]}")
        return
    step_id = ctx.args[1]
    reason = " ".join(ctx.args[2:])
    outcome = TEAM.runner.fail(m.id, step_id, reason=reason)
    TEAM.registry.update_status(status="idle")
    await update.message.reply_text(
        f"Step {step_id} marked FAILED in mission {m.id[:8]}\n"
        f"reason: {reason}",
    )


@authorized_only
async def cmd_handoff(update: Update, ctx: ContextTypes.DEFAULT_TYPE):
    """Hand a mission step off to another agent."""
    if len(ctx.args) < 3:
        await update.message.reply_text(
            "Usage: /handoff <mission_id_prefix> <step_id> <to_agent_id> [note]\n"
            "Use /team to find online agent IDs."
        )
        return
    m = _resolve_mission(ctx.args[0])
    if not m:
        await update.message.reply_text(f"Mission not found: {ctx.args[0]}")
        return
    step_id = ctx.args[1]
    to_agent = ctx.args[2]
    note = " ".join(ctx.args[3:]) if len(ctx.args) > 3 else ""
    outcome = TEAM.runner.handoff(m.id, step_id, to_agent_id=to_agent, note=note)
    if not outcome.success:
        await update.message.reply_text(f"Failed: step {step_id} not found")
        return
    await update.message.reply_text(
        f"Step {step_id} handed off:\n"
        f"  mission: {m.id[:8]}\n"
        f"  to:      {to_agent}\n"
        f"  note:    {outcome.note}",
    )


#
# Skill / Soul / Discovery / Audit
#

@authorized_only
async def cmd_skill_list(update: Update, _ctx: ContextTypes.DEFAULT_TYPE):
    """List indexed skills."""
    vp = TEAM.memory.providers.get("VectorProvider")
    skills = getattr(vp, "skill_index", []) if vp else []
    if not skills:
        await update.message.reply_text("No skills indexed.")
        return
    lines = [f"<b>{len(skills)}</b> skills in registry:\n"]
    for s in skills[:20]:
        name = h(s.get("name", "?"))
        desc = h((s.get("desc") or "")[:70])
        lines.append(f"<code>{name}</code> {desc}")
    if len(skills) > 20:
        lines.append(f"\n<i> and {len(skills)-20} more</i>")
    await update.message.reply_text("\n".join(lines), parse_mode="HTML")


@authorized_only
async def cmd_skill_show(update: Update, ctx: ContextTypes.DEFAULT_TYPE):
    """Show a skill document."""
    if not ctx.args:
        await update.message.reply_text("Usage: /skill_show <skill_id>")
        return
    skill_id = ctx.args[0]
    skill_path = REPO / "skills" / "registry" / f"{skill_id}.md"
    if not skill_path.exists():
        #
        candidates = list((REPO/"skills"/"registry").glob(f"*{skill_id}*.md"))
        if not candidates:
            await update.message.reply_text(f"Skill not found: {skill_id}")
            return
        skill_path = candidates[0]
    content = skill_path.read_text(encoding="utf-8")[:3500]
    await update.message.reply_text(
        f"<b>{h(skill_path.name)}</b>:\n<pre>{h(content)}</pre>",
        parse_mode="HTML",
    )


@authorized_only
async def cmd_soul(update: Update, _ctx: ContextTypes.DEFAULT_TYPE):
    """Show TEAM-SOUL.md."""
    soul_path = REPO / "skills" / "TEAM-SOUL.md"
    if not soul_path.exists():
        await update.message.reply_text("(TEAM-SOUL.md not found)")
        return
    content = soul_path.read_text(encoding="utf-8")[:3500]
    await update.message.reply_text(f"<b>TEAM-SOUL</b>:\n<pre>{h(content)}</pre>", parse_mode="HTML")


@authorized_only
async def cmd_find(update: Update, ctx: ContextTypes.DEFAULT_TYPE):
    """Find online agents by capability."""
    if not ctx.args:
        await update.message.reply_text("Usage: /find <capability>\nExample: /find python")
        return
    cap = ctx.args[0]
    matches = TEAM.finder.find(capability=cap, exclude_agent_ids=[TEAM.agent_id])
    if not matches:
        await update.message.reply_text(
            f" No teammate online with capability `{cap}`\n"
            f"(Just me  `{TEAM.agent_id}`)",
        )
        return
    lines = [f"Found {len(matches)} agent(s) with capability {cap}:\n"]
    for r in matches:
        lines.append(f"{r.agent_id} [{r.status}] on {r.hostname}")
    await update.message.reply_text("\n".join(lines))


@authorized_only
async def cmd_audit(update: Update, _ctx: ContextTypes.DEFAULT_TYPE):
    """Show the latest evolution audit entries."""
    audit_path = REPO / "sidechain" / "evolution_audit.jsonl"
    if not audit_path.exists():
        await update.message.reply_text("No evolution audit found. Run /evolve first.")
        return
    lines_raw = audit_path.read_text(encoding="utf-8").strip().split("\n")
    entries = []
    for line in lines_raw[-5:]:
        try:
            entries.append(json.loads(line))
        except Exception:
            continue
    if not entries:
        await update.message.reply_text(" (parse error)")
        return
    lines = ["Evolution audit (latest 5):\n"]
    for e in entries:
        action = e.get("action", "?")
        skill = e.get("skill_id", "?")
        risk = e.get("risk_level", "?")
        verify = "passed" if e.get("verify_passed") else "failed"
        lines.append(f"{skill} {action} (risk={risk}, verify={verify})")
    await update.message.reply_text("\n".join(lines))


@authorized_only
async def cmd_pending(update: Update, _ctx: ContextTypes.DEFAULT_TYPE):
    """Show pending patches."""
    pending_dir = REPO / "sidechain" / "pending_patches"
    if not pending_dir.exists():
        await update.message.reply_text(" No pending patches awaiting review")
        return
    patches = sorted(pending_dir.glob("*.json"))
    if not patches:
        await update.message.reply_text(" No pending patches awaiting review")
        return
    lines = [f"{len(patches)} pending patch(es):\n"]
    for p in patches[:10]:
        try:
            data = json.loads(p.read_text(encoding="utf-8"))
            patch = data.get("patch", {})
            lines.append(f"{patch.get('skill_id', p.stem)}")
            lines.append(f"    risk: {patch.get('risk_level', '?')} trigger: {patch.get('error_sig', '?')}")
        except Exception:
            lines.append(f" `{p.name}` (parse error)")
    await update.message.reply_text("\n".join(lines))


@authorized_only
async def cmd_help(update: Update, _ctx: ContextTypes.DEFAULT_TYPE):
    """Show bot command help."""
    await update.message.reply_text(
        "<b>NTH DAO Bot Help</b>\n\n"
        "<b>Discovery</b>\n"
        "/team - list online agents\n"
        "/find &lt;capability&gt; - find teammates\n\n"
        "<b>Blackboard</b>\n"
        "/kanban - show TODO/DOING/DONE\n\n"
        "<b>Mission Orchestration</b>\n"
        "/mission_new &lt;title&gt; | &lt;step1&gt; ; &lt;step2&gt;\n"
        "/mission_list - list active missions\n"
        "/mission_show &lt;id&gt; - show mission details\n"
        "/mission_take - claim an actionable step\n"
        "/complete_step &lt;mid&gt; &lt;sid&gt; [note]\n"
        "/fail_step &lt;mid&gt; &lt;sid&gt; &lt;reason&gt;\n"
        "/handoff &lt;mid&gt; &lt;sid&gt; &lt;to_agent&gt; [note]\n\n"
        "<b>Knowledge</b>\n"
        "/skill_list - list indexed skills\n"
        "/skill_show &lt;id&gt; - show a skill document\n"
        "/soul - show TEAM-SOUL.md\n\n"
        "<b>Evolution &amp; Audit</b>\n"
        "/evolve - run EvoLoop once\n"
        "/audit - show latest evolution audit entries\n"
        "/pending - show pending patches\n"
        "/ledger - show recent ledger entries\n\n"
        "<b>Chat</b>\n"
        "Plain text is sent to DeepSeek with NTH DAO context.\n\n"
        "<i>Tip: mission id prefixes of 6-8 chars usually work.</i>",
        parse_mode="HTML",
    )


#
#   DeepSeek
#

SYSTEM_PROMPT_BASE = (
    "You are NTH DAO Bot, a Telegram assistant powered by DeepSeek. "
    "You are part of a multi-agent team using NTH DAO. "
    "Reply concisely (max 200 words unless asked for more)."
)

@authorized_only
async def on_text(update: Update, _ctx: ContextTypes.DEFAULT_TYPE):
    user_text = update.message.text or ""
    user_name = update.effective_user.first_name if update.effective_user else "user"
    logger.info(f"chat from {user_name}: {user_text[:60]}")

    memory_block = TEAM.memory.build_memory_context_block()
    system_prompt = SYSTEM_PROMPT_BASE + "\n\n" + memory_block

    await update.message.chat.send_action("typing")
    error_sig = None
    content = ""
    tokens = 0
    try:
        resp = await asyncio.to_thread(
            get_llm().chat.completions.create,
            model="deepseek-chat",
            messages=[
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": user_text},
            ],
            max_tokens=600,
        )
        content = resp.choices[0].message.content or "(empty)"
        tokens = resp.usage.total_tokens if resp.usage else 0
        logger.info(f"DeepSeek OK: {tokens}t")
    except Exception as e:
        error_sig = f"deepseek_{type(e).__name__}"
        content = f"DeepSeek error: {type(e).__name__}: {str(e)[:200]}"
        logger.error(f"DeepSeek failed: {e}")

    TEAM.memory.providers["LedgerProvider"].record(
        agent_id=TEAM.agent_id,
        action_type="telegram_chat",
        result=content[:200],
        error_sig=error_sig,
        token_cost=tokens,
    )

    if len(content) > 4000:
        content = content[:4000] + "\n...(truncated)"
    await update.message.reply_text(content)

#
#
#

async def post_init(application):
    from telegram import BotCommand

    await application.bot.set_my_commands([
        BotCommand("start", "Start the NTH DAO bot"),
        BotCommand("help", "Show command help"),
        # Discovery
        BotCommand("team", "List online agents"),
        BotCommand("find", "Find agents by capability"),
        # Blackboard
        BotCommand("kanban", "Show the blackboard"),
        # Mission
        BotCommand("mission_new", "Create a mission"),
        BotCommand("mission_list", "List active missions"),
        BotCommand("mission_show", "Show mission details"),
        BotCommand("mission_take", "Claim an actionable step"),
        BotCommand("complete_step", "Complete a step"),
        BotCommand("fail_step", "Fail a step"),
        BotCommand("handoff", "Hand off a step"),
        # Knowledge
        BotCommand("skill_list", "List indexed skills"),
        BotCommand("skill_show", "Show a skill document"),
        BotCommand("soul", "Show TEAM-SOUL.md"),
        # Evolution & Audit
        BotCommand("evolve", "Run EvoLoop once"),
        BotCommand("audit", "Show evolution audit"),
        BotCommand("pending", "Show pending patches"),
        BotCommand("ledger", "Show recent ledger entries"),
    ])
    logger.info("Bot commands registered with Telegram (19 cmds)")


def main():
    # ─────────────────────────────────────────────────────────────────────
    # 已禁用(2026-06-14,产品方向决策)。
    #
    # 这个老 bot 把 NTH DAO runtime 当作"一个大模型的传话筒"直接对外应答 ——
    # 它**自己就是个 agent**。但 NTH DAO 的定位是 **agent 沟通协调的底座**,
    # 我们**不**自建 agent。一个会自己回话的"NTH DAO bot"与这个定位冲突,
    # 还会让用户误以为平台在提供 agent。所以禁止运行。
    #
    # Telegram 的正确接入是 **A2A 桥**:把用户消息**路由到用户自己的 agent**
    # (经 /a2a/ask + 签名校验),平台只做传输,不替 agent 说话。用:
    #     python -m nth_dao.integrations.telegram_bridge
    # 见 nth_dao/integrations/telegram_bridge.py。
    #
    # (import 仍无副作用 —— 守卫只在 run 路径,test_v097_telegram_bot_import
    #  不受影响。)
    raise SystemExit(
        "nth_telegram_bot 已停用:NTH DAO 是 agent 协调底座,不自建会回话的 bot。\n"
        "请改用 A2A 桥(路由到你自己的 agent,带签名校验):\n"
        "    python -m nth_dao.integrations.telegram_bridge")
    _validate_env()
    try:
        from telegram.ext import Application, CommandHandler, MessageHandler, filters
    except ImportError as exc:
        raise RuntimeError(
            "python-telegram-bot is required to run this bot. "
            "Install it before calling main()."
        ) from exc
    app = Application.builder().token(os.environ["TELEGRAM_BOT_TOKEN"]).post_init(post_init).build()

    app.add_handler(CommandHandler("start", cmd_start))
    app.add_handler(CommandHandler("team", cmd_team))
    app.add_handler(CommandHandler("kanban", cmd_kanban))
    app.add_handler(CommandHandler("mission_new", cmd_mission_new))
    app.add_handler(CommandHandler("mission_list", cmd_mission_list))
    app.add_handler(CommandHandler("evolve", cmd_evolve))
    app.add_handler(CommandHandler("ledger", cmd_ledger))
    app.add_handler(CommandHandler("mission_show", cmd_mission_show))
    app.add_handler(CommandHandler("mission_take", cmd_mission_take))
    app.add_handler(CommandHandler("complete_step", cmd_complete_step))
    app.add_handler(CommandHandler("fail_step", cmd_fail_step))
    app.add_handler(CommandHandler("handoff", cmd_handoff))
    app.add_handler(CommandHandler("skill_list", cmd_skill_list))
    app.add_handler(CommandHandler("skill_show", cmd_skill_show))
    app.add_handler(CommandHandler("soul", cmd_soul))
    app.add_handler(CommandHandler("find", cmd_find))
    app.add_handler(CommandHandler("audit", cmd_audit))
    app.add_handler(CommandHandler("pending", cmd_pending))
    app.add_handler(CommandHandler("help", cmd_help))
    app.add_handler(MessageHandler(filters.TEXT & ~filters.COMMAND, on_text))

    allowed = _allowed_users()
    allowed_status = sorted(allowed) if allowed else "OPEN (explicit TELEGRAM_ALLOW_OPEN=1)"
    logger.info("Bot starting (polling)... allowed_users=%s", allowed_status)
    try:
        app.run_polling(drop_pending_updates=True)
    finally:
        logger.info("Detaching NTH DAO...")
        TEAM.detach()


if __name__ == "__main__":
    main()
