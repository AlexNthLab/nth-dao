"""Telegram → A2A 桥:把 Telegram 聊天接到 NTH DAO 的真 agent。

定位(见对话):NTH DAO 是平台,Telegram 退化成它的一个**触达通道**——
补上 NTH DAO 唯一还输给老 telegram bot 的那项:**移动端随身 + 推送**。
不另起炉灶:复用 NodeClient 的 ``/a2a/ask`` + 签名校验,所以每条推回
Telegram 的答复都背书一张该 agent 亲签、绑定内容的 receipt。

数据流:
  Telegram 消息 → NodeClient.ask(did, text) → /api/v2/agents/{did}/ask
    → 远端 hub 注入 cap_token → agent 干活 + 亲签 receipt
    → verify_work_receipt(signer==did + 绑定请求/回应)→ 推回 Telegram。

命令:
  /start          说明
  /agents         列出节点上可驱动的 agent
  /use <label|did> 选定本聊天对话的 agent
  <普通消息>       转给选定(或默认)agent,回签名答复

运行(见 main / 模块尾的环境变量说明)。纯逻辑(format_reply / 路由)
与 Telegram I/O 解耦,便于无 token 测试。
"""

from __future__ import annotations

import asyncio
import os
from typing import Dict, Optional

from nth_dao.integrations.node_client import AskResult, NodeClient, NodeError


def format_reply(res: AskResult) -> str:
    """把 AskResult 格式化成发回 Telegram 的文本(带验签徽标)。"""
    body = res.text.strip() or "(空回复)"
    if res.receipt is None:
        return body + "\n\n— ⚠️ 无签名 receipt(未验证)"
    if res.verified:
        badge = f"✓ 已验签 · signer {res.agent_did[:18]}…"
    else:
        badge = f"⚠️ 验签失败({res.reason})· 勿轻信"
    return f"{body}\n\n— {badge}"


def list_agents_text(node: NodeClient) -> str:
    try:
        ags = node.drivable_agents()
    except NodeError as e:
        return f"⚠️ 取 agent 列表失败:{e}"
    if not ags:
        return "节点上暂无可驱动的 agent(需 supervised+alive+a2a_port)。"
    lines = ["可用 agent(/use <label> 选定):"]
    for a in ags:
        lines.append(f"  • {a.get('label')}  ({a.get('did','')[:16]}…)  "
                     f"caps={a.get('capabilities', [])}")
    return "\n".join(lines)


def resolve_target(
    node: NodeClient, chat_sel: Dict[int, str], chat_id: int,
    default_ref: Optional[str],
) -> Optional[dict]:
    """选定本聊天要驱动的 agent:本聊天 /use 的 > 默认 > None。"""
    ref = chat_sel.get(chat_id) or default_ref
    if not ref:
        return None
    return node.resolve_agent(ref)


def build_application(
    token: str,
    node: NodeClient,
    *,
    default_agent: Optional[str] = None,
):
    """构造 python-telegram-bot Application,把消息接到 NodeClient。"""
    from telegram import Update
    from telegram.ext import (
        Application, CommandHandler, ContextTypes, MessageHandler, filters,
    )

    app = Application.builder().token(token).build()
    chat_sel: Dict[int, str] = {}  # chat_id -> label/did

    async def start(update: "Update", _ctx: "ContextTypes.DEFAULT_TYPE") -> None:
        await update.message.reply_text(
            "NTH DAO ↔ Telegram 桥。\n"
            "/agents 看可用 agent;/use <label> 选定;然后直接发消息即可。\n"
            "每条回复都带该 agent 的签名校验徽标。")

    async def agents_cmd(update: "Update", _ctx) -> None:
        text = await asyncio.get_event_loop().run_in_executor(
            None, list_agents_text, node)
        await update.message.reply_text(text)

    async def use_cmd(update: "Update", ctx) -> None:
        if not ctx.args:
            await update.message.reply_text("用法:/use <label 或 did>")
            return
        ref = ctx.args[0]
        a = await asyncio.get_event_loop().run_in_executor(
            None, node.resolve_agent, ref)
        if a is None:
            await update.message.reply_text(f"找不到可驱动 agent:{ref}")
            return
        chat_sel[update.effective_chat.id] = ref
        await update.message.reply_text(
            f"本聊天已选定 agent:{a.get('label')} ({a.get('did','')[:16]}…)")

    async def on_message(update: "Update", _ctx) -> None:
        chat_id = update.effective_chat.id
        target = await asyncio.get_event_loop().run_in_executor(
            None, resolve_target, node, chat_sel, chat_id, default_agent)
        if target is None:
            await update.message.reply_text(
                "还没选 agent。先 /agents 看一下,再 /use <label> 选定。")
            return
        prompt = update.message.text or ""
        await update.message.chat.send_action("typing")
        try:
            res: AskResult = await asyncio.get_event_loop().run_in_executor(
                None, node.ask, str(target["did"]), prompt)
        except NodeError as e:
            await update.message.reply_text(f"⚠️ 调用失败:{e}")
            return
        await update.message.reply_text(format_reply(res))

    app.add_handler(CommandHandler("start", start))
    app.add_handler(CommandHandler("agents", agents_cmd))
    app.add_handler(CommandHandler("use", use_cmd))
    app.add_handler(MessageHandler(filters.TEXT & ~filters.COMMAND, on_message))
    return app


def main() -> None:
    """环境变量:
      TELEGRAM_BOT_TOKEN   —— BotFather 的 token(必填)
      NTH_NODE_URL         —— 节点 base url(默认 http://127.0.0.1:8088)
      NTH_CONSOLE_TOKEN    —— 节点 Bearer(节点 auth-on 时必填)
      NTH_DEFAULT_AGENT    —— 默认 agent 的 label/did(可选)
    """
    token = os.environ.get("TELEGRAM_BOT_TOKEN", "").strip()
    if not token:
        raise SystemExit("需要 TELEGRAM_BOT_TOKEN")
    node = NodeClient(
        os.environ.get("NTH_NODE_URL", "http://127.0.0.1:8088"),
        os.environ.get("NTH_CONSOLE_TOKEN") or None,
    )
    app = build_application(
        token, node, default_agent=os.environ.get("NTH_DEFAULT_AGENT") or None)
    print("Telegram ↔ A2A 桥启动,polling…", flush=True)
    app.run_polling()


if __name__ == "__main__":
    main()
