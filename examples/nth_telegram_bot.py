"""
Nth Team Layer Telegram Bot — 把 Nth Team Layer 暴露到 Telegram

启动：
    python nth_telegram_bot.py

需要 ~/.hermes/.env 里有:
    KEDELAW_BOT_TOKEN=...
    KEDELAW_ALLOWED_USERS=<comma-separated user IDs>
    DEEPSEEK_API_KEY=...

命令：
    /start           欢迎 + 命令列表
    /team            列出在线 agent (Discovery)
    /kanban          Blackboard kanban 视图
    /mission_new <title> | <step1> ; <step2>
                     新建 mission (步骤用 | 和 ; 分隔)
    /mission_list    列出所有 active mission
    /evolve          触发 EvoLoop.run_once()
    /ledger          ledger 统计 (近 10 条)
    任意文本         调 DeepSeek 回答 + 记入 ledger

设计：
- 共用同一个 workspace ~/Desktop/hermes-team-agent 的 nth 子系统
- 自己 attach() 一个 'telegram-bot' agent，让你的 Mission/Blackboard 操作有人格化的发起者
- LLM 直接走 openai SDK + DeepSeek（不通过 hermes 中间层）

模块契约（Module Contract）：
- 本模块可安全 import，不会触发 SystemExit 或文件 I/O 副作用
- CLI 入口（__name__ == "__main__"）通过 main() → _validate_env() 在启动时校验环境变量
- 作为库导入时，调用方负责确保 KEDELAW_BOT_TOKEN 和 DEEPSEEK_API_KEY 已设置
- 测试代码应在 import 前注入假环境变量：
    os.environ.setdefault("KEDELAW_BOT_TOKEN", "fake-token")
    os.environ.setdefault("DEEPSEEK_API_KEY", "fake-key")
- DeepSeek 客户端通过 get_llm() 惰性初始化，首次调用时才真正连接
"""

import asyncio
import json
import logging
import os
import sys
from pathlib import Path

# Windows UTF-8
if sys.platform == "win32":
    try:
        sys.stdout.reconfigure(encoding="utf-8")
        sys.stderr.reconfigure(encoding="utf-8")
    except AttributeError:
        pass

# 1. 加载 ~/.hermes/.env
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

# 2. 模块级 env（可安全 import，不触发 SystemExit）
TOKEN = os.environ.get("KEDELAW_BOT_TOKEN")
ALLOWED = {u.strip() for u in os.environ.get("KEDELAW_ALLOWED_USERS", "").split(",") if u.strip()}


def _validate_env():
    """Raise RuntimeError if required env vars are missing.

    Called by the CLI entry point; silently safe to import without env vars.
    """
    missing = []
    if not os.environ.get("KEDELAW_BOT_TOKEN"):
        missing.append("KEDELAW_BOT_TOKEN")
    if not os.environ.get("DEEPSEEK_API_KEY"):
        missing.append("DEEPSEEK_API_KEY")
    if missing:
        raise RuntimeError(
            f"Missing required env vars: {' '.join(missing)}. "
            f"Set them in ~/.hermes/.env"
        )

# 3. 加载 nth_team_layer
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
import nth_team_layer as nth
from nth_team_layer import render_kanban           # facade re-export
from nth_team_layer.orchestration import StepStatus

# 4. openai SDK for DeepSeek
from openai import OpenAI

# 5. telegram
from telegram import Update, BotCommand
from telegram.ext import (
    Application, CommandHandler, MessageHandler, ContextTypes, filters,
)

# ─────────────────────────────────────────────────────────────────
# 日志
# ─────────────────────────────────────────────────────────────────

logging.basicConfig(
    format="%(asctime)s %(levelname)s %(name)s: %(message)s",
    level=logging.INFO,
)
logger = logging.getLogger("nth-bot")
# 抑制 telegram 库的 verbose 日志
logging.getLogger("httpx").setLevel(logging.WARNING)
logging.getLogger("telegram").setLevel(logging.WARNING)

# ─────────────────────────────────────────────────────────────────
# Nth Team Layer 启动
# ─────────────────────────────────────────────────────────────────

REPO = Path(__file__).resolve().parent.parent
TEAM = nth.attach(
    agent_id="kede-agent",
    backend=None,                                  # 我们自己直接调 DeepSeek
    capabilities=["chat", "telegram", "qa"],
    groups=["bots"],
    workspace=REPO,
    start_heartbeat=True,                          # 持续心跳让其他 agent 知道我们在线
)
logger.info(f"Nth Team Layer attached: {TEAM.agent_id} on {TEAM.workspace}")

# DeepSeek client (lazy init — safe to import without DEEPSEEK_API_KEY)
_llm: OpenAI | None = None


def get_llm() -> OpenAI:
    """Return the shared DeepSeek client, initializing on first call.

    Raises RuntimeError if DEEPSEEK_API_KEY is not set.
    """
    global _llm
    if _llm is None:
        key = os.environ.get("DEEPSEEK_API_KEY")
        if not key:
            raise RuntimeError(
                "DEEPSEEK_API_KEY not set. Set it in ~/.hermes/.env"
            )
        _llm = OpenAI(api_key=key, base_url="https://api.deepseek.com/v1")
    return _llm

# ─────────────────────────────────────────────────────────────────
# 权限装饰器
# ─────────────────────────────────────────────────────────────────

def authorized_only(handler):
    """只允许 ALLOWED 列表里的 user_id 调用 + 自动记录每个命令的触发"""
    async def wrapper(update: Update, context: ContextTypes.DEFAULT_TYPE):
        uid = str(update.effective_user.id) if update.effective_user else ""
        if ALLOWED and uid not in ALLOWED:
            logger.warning(f"DENY user_id={uid} (not in allowlist)")
            await update.message.reply_text(
                f"⛔ Unauthorized (user_id={uid}). Ask admin to add you to KEDELAW_ALLOWED_USERS."
            )
            return
        # 记录命令触发（便于诊断 + 让后台 monitor 看到全部测试动作）
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
                    f"⚠️ Internal error in {handler.__name__}: {type(e).__name__}: {str(e)[:200]}"
                )
            except Exception:
                pass
    return wrapper

# ─────────────────────────────────────────────────────────────────
# 命令 Handlers
# ─────────────────────────────────────────────────────────────────

@authorized_only
async def cmd_start(update: Update, _ctx: ContextTypes.DEFAULT_TYPE):
    await update.message.reply_text(
        "🤖 Nth Team Layer Bot — 已就绪\n\n"
        "命令：\n"
        "/team — 在线 agent 列表\n"
        "/kanban — Blackboard 看板\n"
        "/mission_new <标题> | <步骤1> ; <步骤2> ; ...\n"
        "    例: /mission_new ship payments | design api ; build ui ; e2e tests\n"
        "/mission_list — 所有进行中 mission\n"
        "/evolve — 触发 EvoLoop.run_once()\n"
        "/ledger — 最近 ledger 条目\n\n"
        "直接发文本 → 我用 DeepSeek 回答你（同时记入 ledger）"
    )

@authorized_only
async def cmd_team(update: Update, _ctx: ContextTypes.DEFAULT_TYPE):
    online = TEAM.registry.list_alive()
    if not online:
        await update.message.reply_text("(no agents online)")
        return
    lines = ["🟢 在线 Agent:\n"]
    for r in online:
        caps = ",".join(r.capabilities[:3]) or "-"
        lines.append(f"• `{r.agent_id}` [{r.status}]  caps=[{caps}]  on {r.hostname}")
    await update.message.reply_text("\n".join(lines), parse_mode="Markdown")

@authorized_only
async def cmd_kanban(update: Update, _ctx: ContextTypes.DEFAULT_TYPE):
    entries = TEAM.blackboard.list()
    if not entries:
        await update.message.reply_text("📋 Blackboard 空。/mission_new 来加些任务")
        return
    kanban_text = render_kanban(entries, width=22)
    # Telegram 消息长度限制 4096 + Markdown code block
    if len(kanban_text) > 3800:
        kanban_text = kanban_text[:3800] + "\n... (truncated)"
    await update.message.reply_text(f"```\n{kanban_text}\n```", parse_mode="Markdown")

@authorized_only
async def cmd_mission_new(update: Update, ctx: ContextTypes.DEFAULT_TYPE):
    args = " ".join(ctx.args) if ctx.args else ""
    if "|" not in args:
        await update.message.reply_text(
            "用法: /mission_new <标题> | <步骤1> ; <步骤2> ; ...\n"
            "例: /mission_new ship payments | design api ; build ui ; e2e tests"
        )
        return
    title, _, steps_part = args.partition("|")
    title = title.strip()
    steps_descs = [s.strip() for s in steps_part.split(";") if s.strip()]
    if not steps_descs:
        await update.message.reply_text("至少需要 1 个步骤（用 ; 分隔）")
        return
    steps = [
        {"id": f"step-{i+1}", "description": d, "depends_on": [f"step-{i}"] if i > 0 else []}
        for i, d in enumerate(steps_descs)
    ]
    mission = TEAM.start_mission(title=title, goal=title, steps=steps)
    short_id = mission.id[:8]
    step_examples = "\n".join([
        f"  /complete_step {short_id} {s['id']} 完成笔记"
        for s in steps[:2]
    ])
    await update.message.reply_text(
        f"✅ <b>Mission created</b>\n\n"
        f"id:    <code>{mission.id}</code>\n"
        f"title: {mission.title}\n"
        f"steps: {len(steps)} ({', '.join(s['id'] for s in steps)})\n\n"
        f"💡 <b>下一步可以用</b>（短 ID = <code>{short_id}</code>）:\n"
        f"  /mission_take             (自动 claim)\n"
        f"  /mission_show {short_id}\n"
        f"{step_examples}",
        parse_mode="HTML",
    )

@authorized_only
async def cmd_mission_list(update: Update, _ctx: ContextTypes.DEFAULT_TYPE):
    missions = TEAM.mission_store.list_active()
    if not missions:
        await update.message.reply_text("(no active missions)")
        return
    lines = ["📦 Active Missions:\n"]
    for m in missions[:10]:
        p = m.progress()
        lines.append(
            f"• `{m.id}` {m.title}\n"
            f"  status: {m.status} | {p['done']}/{p['total']} done ({p['percent']}%)"
        )
    await update.message.reply_text("\n".join(lines), parse_mode="Markdown")

@authorized_only
async def cmd_evolve(update: Update, _ctx: ContextTypes.DEFAULT_TYPE):
    from team_layer.evolution import EvoLoop
    ledger = TEAM.memory.providers["LedgerProvider"]
    loop = EvoLoop(ledger=ledger)
    results = loop.run_once()
    if not results:
        await update.message.reply_text("🧬 No error signatures crossed ROI threshold yet.")
        return
    lines = [f"🧬 Evolved {len(results)} signature(s):\n"]
    for r in results:
        sig = r.decision.error_sig
        gate = r.gate.action.value if r.gate else "no-gate"
        lines.append(f"• `{sig}` → {gate}")
    await update.message.reply_text("\n".join(lines), parse_mode="Markdown")

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
        await update.message.reply_text("📒 Ledger 空")
        return
    lines = ["📒 Recent ledger entries:\n"]
    for e in entries[-10:]:
        sig = e.get("error_sig") or "ok"
        lines.append(f"• [{sig[:20]}] cost={e.get('token_cost',0)}t action={e.get('action_type','?')[:25]}")
    await update.message.reply_text("\n".join(lines))


# ─────────────────────────────────────────────────────────────────
# Mission 接力命令组（PR 8 MissionRunner 暴露到 Telegram）
# ─────────────────────────────────────────────────────────────────

def _resolve_mission(mission_id_prefix: str):
    """支持 mission_id 前缀匹配（不必输完整 12 字符）"""
    for m in TEAM.mission_store.list_active():
        if m.id.startswith(mission_id_prefix):
            return m
    return None


@authorized_only
async def cmd_mission_show(update: Update, ctx: ContextTypes.DEFAULT_TYPE):
    """显示一个 Mission 的完整步骤 + 历史 notes"""
    if not ctx.args:
        await update.message.reply_text("用法: /mission_show <mission_id 前缀>")
        return
    m = _resolve_mission(ctx.args[0])
    if not m:
        await update.message.reply_text(f"找不到 mission `{ctx.args[0]}*`", parse_mode="Markdown")
        return
    p = m.progress()
    lines = [
        f"📦 *{m.title}*  `{m.id}`",
        f"status: {m.status}  |  {p['done']}/{p['total']} done ({p['percent']}%)",
        f"owner:  {m.owner}",
        f"scope:  {m.scope}",
        "",
        "*Steps:*",
    ]
    for s in m.steps:
        assignee = s.assignee or "—"
        deps = f" deps={s.depends_on}" if s.depends_on else ""
        lines.append(f"• `{s.id}` \\[{s.status}] {s.description[:60]}  by `{assignee}`{deps}")
        for note in s.notes[-2:]:
            lines.append(f"    📝 {note[:100]}")
    await update.message.reply_text("\n".join(lines), parse_mode="Markdown")


@authorized_only
async def cmd_mission_take(update: Update, _ctx: ContextTypes.DEFAULT_TYPE):
    """自动找一个 capability 匹配的可执行 step 并 claim"""
    found = TEAM.runner.find_work()
    if not found:
        await update.message.reply_text(
            "🤷 No actionable step matching capabilities=" + str(TEAM.capabilities)
        )
        return
    m, s = found
    TEAM.runner.claim(m.id, s.id)
    TEAM.registry.update_status(status="busy", current_mission=m.id)
    await update.message.reply_text(
        f"🎯 Claimed step:\n"
        f"mission: `{m.id}` {m.title}\n"
        f"step:    `{s.id}` {s.description}\n"
        f"现在你可以做完后调 /complete\\_step {m.id[:8]} {s.id}",
        parse_mode="Markdown",
    )


@authorized_only
async def cmd_complete_step(update: Update, ctx: ContextTypes.DEFAULT_TYPE):
    """完成一个 step: /complete_step <mid> <sid> [note...]"""
    if len(ctx.args) < 2:
        await update.message.reply_text("用法: /complete_step <mission_id> <step_id> [备注]")
        return
    m = _resolve_mission(ctx.args[0])
    if not m:
        await update.message.reply_text(f"找不到 mission `{ctx.args[0]}*`")
        return
    step_id = ctx.args[1]
    note = " ".join(ctx.args[2:]) if len(ctx.args) > 2 else "completed via telegram"
    outcome = TEAM.runner.complete(m.id, step_id, note=note)
    if not outcome.success:
        await update.message.reply_text(f"❌ Failed: step `{step_id}` not found")
        return
    TEAM.registry.update_status(status="idle")
    # 检查 Mission 是否随之完成
    fresh = TEAM.mission_store.get(m.id)
    extra = "\n🎉 Mission 全部完成！" if fresh and fresh.is_finished() else ""
    await update.message.reply_text(
        f"✅ Step `{step_id}` marked DONE in mission `{m.id[:8]}`\n"
        f"note: {note}{extra}",
        parse_mode="Markdown",
    )


@authorized_only
async def cmd_fail_step(update: Update, ctx: ContextTypes.DEFAULT_TYPE):
    """标记 step 失败: /fail_step <mid> <sid> <reason...>"""
    if len(ctx.args) < 3:
        await update.message.reply_text("用法: /fail_step <mission_id> <step_id> <原因>")
        return
    m = _resolve_mission(ctx.args[0])
    if not m:
        await update.message.reply_text(f"找不到 mission `{ctx.args[0]}*`")
        return
    step_id = ctx.args[1]
    reason = " ".join(ctx.args[2:])
    outcome = TEAM.runner.fail(m.id, step_id, reason=reason)
    TEAM.registry.update_status(status="idle")
    await update.message.reply_text(
        f"💥 Step `{step_id}` marked FAILED in mission `{m.id[:8]}`\n"
        f"reason: {reason}",
        parse_mode="Markdown",
    )


@authorized_only
async def cmd_handoff(update: Update, ctx: ContextTypes.DEFAULT_TYPE):
    """接力: /handoff <mid> <sid> <to_agent_id> [note]"""
    if len(ctx.args) < 3:
        await update.message.reply_text(
            "用法: /handoff <mission_id> <step_id> <to_agent_id> [备注]\n"
            "to_agent_id 可以在 /team 看到"
        )
        return
    m = _resolve_mission(ctx.args[0])
    if not m:
        await update.message.reply_text(f"找不到 mission `{ctx.args[0]}*`")
        return
    step_id = ctx.args[1]
    to_agent = ctx.args[2]
    note = " ".join(ctx.args[3:]) if len(ctx.args) > 3 else ""
    outcome = TEAM.runner.handoff(m.id, step_id, to_agent_id=to_agent, note=note)
    if not outcome.success:
        await update.message.reply_text(f"❌ Failed: step `{step_id}` not found")
        return
    await update.message.reply_text(
        f"🤝 Step `{step_id}` handed off:\n"
        f"  mission: `{m.id[:8]}`\n"
        f"  to:      `{to_agent}`\n"
        f"  note:    {outcome.note}",
        parse_mode="Markdown",
    )


# ─────────────────────────────────────────────────────────────────
# Skill / Soul / Discovery / Audit
# ─────────────────────────────────────────────────────────────────

@authorized_only
async def cmd_skill_list(update: Update, _ctx: ContextTypes.DEFAULT_TYPE):
    """列出所有 skills/registry/ 下技能（HTML mode — 容忍 desc 里的特殊字符）"""
    from html import escape as h
    vp = TEAM.memory.providers.get("VectorProvider")
    skills = getattr(vp, "skill_index", []) if vp else []
    if not skills:
        await update.message.reply_text("📚 (no skills indexed)")
        return
    lines = [f"📚 <b>{len(skills)}</b> skills in registry:\n"]
    for s in skills[:20]:
        name = h(s.get("name", "?"))
        desc = h((s.get("desc") or "")[:70])
        lines.append(f"• <code>{name}</code> — {desc}")
    if len(skills) > 20:
        lines.append(f"\n<i>… and {len(skills)-20} more</i>")
    await update.message.reply_text("\n".join(lines), parse_mode="HTML")


@authorized_only
async def cmd_skill_show(update: Update, ctx: ContextTypes.DEFAULT_TYPE):
    """显示一个 skill 的完整内容"""
    if not ctx.args:
        await update.message.reply_text("用法: /skill_show <skill_id>")
        return
    skill_id = ctx.args[0]
    skill_path = REPO / "skills" / "registry" / f"{skill_id}.md"
    if not skill_path.exists():
        # 尝试模糊匹配
        candidates = list((REPO/"skills"/"registry").glob(f"*{skill_id}*.md"))
        if not candidates:
            await update.message.reply_text(f"找不到 skill `{skill_id}`")
            return
        skill_path = candidates[0]
    content = skill_path.read_text(encoding="utf-8")[:3500]
    await update.message.reply_text(
        f"📄 `{skill_path.name}`:\n```\n{content}\n```",
        parse_mode="Markdown",
    )


@authorized_only
async def cmd_soul(update: Update, _ctx: ContextTypes.DEFAULT_TYPE):
    """显示 TEAM-SOUL.md"""
    soul_path = REPO / "skills" / "TEAM-SOUL.md"
    if not soul_path.exists():
        await update.message.reply_text("(TEAM-SOUL.md not found)")
        return
    content = soul_path.read_text(encoding="utf-8")[:3500]
    await update.message.reply_text(f"🧠 *TEAM-SOUL:*\n```\n{content}\n```", parse_mode="Markdown")


@authorized_only
async def cmd_find(update: Update, ctx: ContextTypes.DEFAULT_TYPE):
    """按 capability 找队友: /find <capability>"""
    if not ctx.args:
        await update.message.reply_text("用法: /find <capability>  例: /find python")
        return
    cap = ctx.args[0]
    matches = TEAM.finder.find(capability=cap, exclude_agent_ids=[TEAM.agent_id])
    if not matches:
        await update.message.reply_text(
            f"🔍 No teammate online with capability `{cap}`\n"
            f"(Just me — `{TEAM.agent_id}`)",
            parse_mode="Markdown",
        )
        return
    lines = [f"🔍 Found {len(matches)} agent(s) with capability `{cap}`:\n"]
    for r in matches:
        lines.append(f"• `{r.agent_id}` [{r.status}] on {r.hostname}")
    await update.message.reply_text("\n".join(lines), parse_mode="Markdown")


@authorized_only
async def cmd_audit(update: Update, _ctx: ContextTypes.DEFAULT_TYPE):
    """显示 evolution_audit.jsonl 最近 5 条"""
    audit_path = REPO / "sidechain" / "evolution_audit.jsonl"
    if not audit_path.exists():
        await update.message.reply_text("📜 Evolution audit 空（EvoLoop 还没跑过）")
        return
    lines_raw = audit_path.read_text(encoding="utf-8").strip().split("\n")
    entries = []
    for line in lines_raw[-5:]:
        try:
            entries.append(json.loads(line))
        except Exception:
            continue
    if not entries:
        await update.message.reply_text("📜 (parse error)")
        return
    lines = ["📜 *Evolution Audit (近 5 条):*\n"]
    for e in entries:
        action = e.get("action", "?")
        skill = e.get("skill_id", "?")
        risk = e.get("risk_level", "?")
        verify = "✓" if e.get("verify_passed") else "✗"
        lines.append(f"• `{skill}` → {action} (risk={risk}, verify={verify})")
    await update.message.reply_text("\n".join(lines), parse_mode="Markdown")


@authorized_only
async def cmd_pending(update: Update, _ctx: ContextTypes.DEFAULT_TYPE):
    """列出待人工审批的 patch (PENDING_REVIEW)"""
    pending_dir = REPO / "sidechain" / "pending_patches"
    if not pending_dir.exists():
        await update.message.reply_text("✅ No pending patches awaiting review")
        return
    patches = sorted(pending_dir.glob("*.json"))
    if not patches:
        await update.message.reply_text("✅ No pending patches awaiting review")
        return
    lines = [f"⚠️ *{len(patches)} pending patch(es):*\n"]
    for p in patches[:10]:
        try:
            data = json.loads(p.read_text(encoding="utf-8"))
            patch = data.get("patch", {})
            lines.append(f"• `{patch.get('skill_id', p.stem)}`")
            lines.append(f"    risk: {patch.get('risk_level', '?')}  trigger: `{patch.get('error_sig', '?')}`")
        except Exception:
            lines.append(f"• `{p.name}` (parse error)")
    await update.message.reply_text("\n".join(lines), parse_mode="Markdown")


@authorized_only
async def cmd_help(update: Update, _ctx: ContextTypes.DEFAULT_TYPE):
    """完整命令清单（按子系统分组，HTML mode 避免 < > 等字符崩 parser）"""
    await update.message.reply_text(
        "🤖 <b>Nth Team Layer Bot — 全部命令</b>\n\n"
        "👥 <b>Discovery</b>\n"
        "/team — 在线 agent 列表\n"
        "/find &lt;cap&gt; — 按能力找队友\n\n"
        "📋 <b>Blackboard</b>\n"
        "/kanban — TODO/DOING/DONE 看板\n\n"
        "📦 <b>Mission Orchestration</b>\n"
        "/mission_new &lt;title&gt; | &lt;step1&gt; ; &lt;step2&gt; — 新建\n"
        "/mission_list — 进行中\n"
        "/mission_show &lt;id&gt; — 详情 + 接力链\n"
        "/mission_take — 自动 claim 一个匹配 step\n"
        "/complete_step &lt;mid&gt; &lt;sid&gt; [note]\n"
        "/fail_step &lt;mid&gt; &lt;sid&gt; &lt;reason&gt;\n"
        "/handoff &lt;mid&gt; &lt;sid&gt; &lt;to_agent&gt; [note]\n\n"
        "📚 <b>Knowledge</b>\n"
        "/skill_list — 所有 skills/registry/\n"
        "/skill_show &lt;id&gt; — 显示一个 skill\n"
        "/soul — TEAM-SOUL.md\n\n"
        "🧬 <b>Evolution &amp; Audit</b>\n"
        "/evolve — 触发 EvoLoop\n"
        "/audit — 近 5 条 evolution audit\n"
        "/pending — 待人工审批的 patch\n"
        "/ledger — 近 10 条 ledger\n\n"
        "💬 <b>Chat</b>\n"
        "直接发文本 → DeepSeek v4 回答 + 记入 ledger\n\n"
        "💡 <i>提示: 提到 mission_id 只需前 6-8 位前缀</i>",
        parse_mode="HTML",
    )


# ─────────────────────────────────────────────────────────────────
# 自由文本 → DeepSeek
# ─────────────────────────────────────────────────────────────────

SYSTEM_PROMPT_BASE = (
    "You are Nth Team Bot, a Telegram assistant powered by DeepSeek. "
    "You are part of a multi-agent team using Nth Team Layer. "
    "Reply concisely (max 200 words unless asked for more)."
)

@authorized_only
async def on_text(update: Update, _ctx: ContextTypes.DEFAULT_TYPE):
    user_text = update.message.text or ""
    user_name = update.effective_user.first_name if update.effective_user else "user"
    logger.info(f"chat from {user_name}: {user_text[:60]}")

    # 注入 Team Layer 记忆上下文
    memory_block = TEAM.memory.build_memory_context_block()
    system_prompt = SYSTEM_PROMPT_BASE + "\n\n" + memory_block

    # 调 DeepSeek
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
        content = f"⚠️ DeepSeek error: {type(e).__name__}: {str(e)[:200]}"
        logger.error(f"DeepSeek failed: {e}")

    # 记入 ledger
    TEAM.memory.providers["LedgerProvider"].record(
        agent_id=TEAM.agent_id,
        action_type="telegram_chat",
        result=content[:200],
        error_sig=error_sig,
        token_cost=tokens,
    )

    # 回 Telegram
    if len(content) > 4000:
        content = content[:4000] + "\n...(truncated)"
    await update.message.reply_text(content)

# ─────────────────────────────────────────────────────────────────
# 启动
# ─────────────────────────────────────────────────────────────────

async def post_init(application):
    await application.bot.set_my_commands([
        BotCommand("start", "欢迎"),
        BotCommand("help", "完整命令清单"),
        # Discovery
        BotCommand("team", "在线 agent 列表"),
        BotCommand("find", "按能力找队友: /find <capability>"),
        # Blackboard
        BotCommand("kanban", "Blackboard 看板"),
        # Mission
        BotCommand("mission_new", "新建 Mission: <title> | <step1> ; <step2>"),
        BotCommand("mission_list", "进行中的 Mission"),
        BotCommand("mission_show", "Mission 详情: /mission_show <id>"),
        BotCommand("mission_take", "自动 claim 一个匹配 step"),
        BotCommand("complete_step", "完成 step: <mid> <sid> [note]"),
        BotCommand("fail_step", "标记 step 失败: <mid> <sid> <reason>"),
        BotCommand("handoff", "接力: <mid> <sid> <to_agent>"),
        # Knowledge
        BotCommand("skill_list", "全部技能"),
        BotCommand("skill_show", "看技能内容: /skill_show <id>"),
        BotCommand("soul", "团队灵魂 TEAM-SOUL.md"),
        # Evolution & Audit
        BotCommand("evolve", "触发 EvoLoop"),
        BotCommand("audit", "evolution_audit 近 5 条"),
        BotCommand("pending", "待人工审批的 patch"),
        BotCommand("ledger", "近 10 条 ledger"),
    ])
    logger.info("Bot commands registered with Telegram (19 cmds)")


def main():
    _validate_env()
    app = Application.builder().token(TOKEN).post_init(post_init).build()

    # 现有 7 个
    app.add_handler(CommandHandler("start", cmd_start))
    app.add_handler(CommandHandler("team", cmd_team))
    app.add_handler(CommandHandler("kanban", cmd_kanban))
    app.add_handler(CommandHandler("mission_new", cmd_mission_new))
    app.add_handler(CommandHandler("mission_list", cmd_mission_list))
    app.add_handler(CommandHandler("evolve", cmd_evolve))
    app.add_handler(CommandHandler("ledger", cmd_ledger))
    # PR 8 接力命令组
    app.add_handler(CommandHandler("mission_show", cmd_mission_show))
    app.add_handler(CommandHandler("mission_take", cmd_mission_take))
    app.add_handler(CommandHandler("complete_step", cmd_complete_step))
    app.add_handler(CommandHandler("fail_step", cmd_fail_step))
    app.add_handler(CommandHandler("handoff", cmd_handoff))
    # 知识 / Audit
    app.add_handler(CommandHandler("skill_list", cmd_skill_list))
    app.add_handler(CommandHandler("skill_show", cmd_skill_show))
    app.add_handler(CommandHandler("soul", cmd_soul))
    app.add_handler(CommandHandler("find", cmd_find))
    app.add_handler(CommandHandler("audit", cmd_audit))
    app.add_handler(CommandHandler("pending", cmd_pending))
    app.add_handler(CommandHandler("help", cmd_help))
    app.add_handler(MessageHandler(filters.TEXT & ~filters.COMMAND, on_text))

    logger.info(f"Bot starting (polling)... allowed_users={ALLOWED or '(open)'}")
    try:
        app.run_polling(drop_pending_updates=True)
    finally:
        logger.info("Detaching Nth Team Layer...")
        TEAM.detach()


if __name__ == "__main__":
    main()
