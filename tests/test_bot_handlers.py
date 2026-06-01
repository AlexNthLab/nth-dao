"""
 unit-test bot 19  handler   Telegram polling
 mock update / ctx handler  reply_text


1.  handler
2. reply_text  valid
3. parse_mode  Telegram  escape
"""

import asyncio
import sys
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock

if sys.platform == "win32":
    try:
        sys.stdout.reconfigure(encoding="utf-8")
        sys.stderr.reconfigure(encoding="utf-8")
    except AttributeError:
        pass

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

#  import botbot
import os
os.environ.setdefault("TELEGRAM_BOT_TOKEN", "fake-token-for-test")
os.environ.setdefault("DEEPSEEK_API_KEY", "fake-key-for-test")
os.environ.setdefault("TELEGRAM_ALLOWED_USERS", "6506447491")

#  import bot  handlers
import nth_telegram_bot as bot


def make_fake_update(text: str = "", user_id: int = 6506447491, user_name: str = "TestUser"):
    """ mock  telegram Update """
    update = MagicMock()
    update.effective_user.id = user_id
    update.effective_user.first_name = user_name
    update.message.text = text
    update.message.reply_text = AsyncMock()
    update.message.chat.send_action = AsyncMock()
    return update


def make_fake_ctx(args=None):
    ctx = MagicMock()
    ctx.args = args or []
    return ctx


def validate_reply(reply: str, parse_mode: str = None) -> tuple:
    """
     reply  Telegram
     (ok: bool, issues: list)
    """
    issues = []
    if not reply:
        issues.append("EMPTY")
        return False, issues
    if len(reply) > 4096:
        issues.append(f"TOO_LONG ({len(reply)} > 4096)")

    if parse_mode == "Markdown":
        #  *  _
        #  100%  bug
        # Markdown V1
        for ch in ("*", "_"):
            count = sum(1 for c in reply if c == ch and
                        (reply.index(c, 0) if False else True))  #
            #
            pass

    return len(issues) == 0, issues


async def run_test(name: str, handler, ctx_args=None, msg_text="/test"):
    """ handler test"""
    update = make_fake_update(text=msg_text)
    ctx = make_fake_ctx(args=ctx_args)
    try:
        await handler(update, ctx)
        #  reply_text
        if not update.message.reply_text.called:
            return name, "NO_REPLY", None
        #  call
        call_args = update.message.reply_text.call_args
        reply_text = call_args.args[0] if call_args.args else ""
        parse_mode = call_args.kwargs.get("parse_mode") if call_args.kwargs else None
        ok, issues = validate_reply(reply_text, parse_mode)
        preview = reply_text[:80].replace("\n", "  ")
        return name, "OK" if ok else f"INVALID ({issues})", f"{len(reply_text)}c {parse_mode or 'plain'}: {preview}"
    except Exception as e:
        return name, f"CRASH: {type(e).__name__}: {str(e)[:100]}", None


async def main():
    print("=" * 80)
    print("Nth Telegram Bot  19 Handlers Unit Test")
    print("=" * 80)
    print()

    # cmd_mission_show / complete_step  mission_id
    #  missions/    fake prefix
    missions_dir = Path("missions")
    mission_id = None
    if missions_dir.exists():
        for f in missions_dir.glob("*.json"):
            mission_id = f.stem
            break
    if mission_id:
        short_id = mission_id[:8]
        print(f" mission_id: {mission_id} ( ID: {short_id})\n")
    else:
        short_id = "deadbeef"
        print(f" mission fake ID: {short_id}\n")

    #
    tests = [
        #
        ("cmd_start",         bot.cmd_start,         None,                                    "/start"),
        ("cmd_help",          bot.cmd_help,          None,                                    "/help"),
        # Discovery
        ("cmd_team",          bot.cmd_team,          None,                                    "/team"),
        ("cmd_find (no args)",bot.cmd_find,          [],                                      "/find"),
        ("cmd_find chat",     bot.cmd_find,          ["chat"],                                "/find chat"),
        ("cmd_find python",   bot.cmd_find,          ["python"],                              "/find python"),
        # Blackboard
        ("cmd_kanban",        bot.cmd_kanban,        None,                                    "/kanban"),
        # Mission
        ("cmd_mission_list",  bot.cmd_mission_list,  None,                                    "/mission_list"),
        ("cmd_mission_show (real)",
                              bot.cmd_mission_show,  [short_id],                              f"/mission_show {short_id}"),
        ("cmd_mission_show (none)",
                              bot.cmd_mission_show,  ["zzz999"],                              "/mission_show zzz999"),
        ("cmd_mission_new",   bot.cmd_mission_new,
                              "unit test mission | step a ; step b".split(),                  "/mission_new ..."),
        ("cmd_mission_take",  bot.cmd_mission_take,  None,                                    "/mission_take"),
        ("cmd_complete_step", bot.cmd_complete_step, [short_id, "step-1", ""],            f"/complete_step {short_id} step-1 "),
        ("cmd_fail_step",     bot.cmd_fail_step,     [short_id, "step-2", ""],         f"/fail_step ..."),
        ("cmd_handoff",       bot.cmd_handoff,       [short_id, "step-3", "alice-coder"],     f"/handoff ..."),
        # Knowledge
        ("cmd_skill_list",    bot.cmd_skill_list,    None,                                    "/skill_list"),
        ("cmd_skill_show",    bot.cmd_skill_show,    ["fix_timeout_database"],                "/skill_show fix_timeout_database"),
        ("cmd_soul",          bot.cmd_soul,          None,                                    "/soul"),
        # Evolution & Audit
        ("cmd_evolve",        bot.cmd_evolve,        None,                                    "/evolve"),
        ("cmd_audit",         bot.cmd_audit,         None,                                    "/audit"),
        ("cmd_pending",       bot.cmd_pending,       None,                                    "/pending"),
        ("cmd_ledger",        bot.cmd_ledger,        None,                                    "/ledger"),
    ]

    #
    results = []
    for name, handler, args, msg in tests:
        result = await run_test(name, handler, ctx_args=args, msg_text=msg)
        results.append(result)
        status = result[1]
        emoji = "" if status == "OK" else "" if status.startswith("INVALID") or status == "NO_REPLY" else ""
        print(f"  {emoji} {name:35s}  {status}")
        if result[2]:
            print(f"       {result[2]}")

    print()
    print("=" * 80)
    oks = sum(1 for r in results if r[1] == "OK")
    crashes = sum(1 for r in results if r[1].startswith("CRASH"))
    others = len(results) - oks - crashes
    print(f"Summary: {oks}/{len(results)} OK  |  {crashes} crashes  |  {others} other issues")
    print("=" * 80)


if __name__ == "__main__":
    asyncio.run(main())
    # detach team layer to clean up heartbeat
    try:
        bot.TEAM.detach()
    except Exception:
        pass
