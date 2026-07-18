"""确定性验收器（CS2b）—— 第一个 SKU：nth.test-execution.v1。

交易路线图 §9.1 的首个可交易商品：对指定 Git commit 跑指定测试命令，
交付一张 worker 签名的 execution receipt（pin commit / command /
exit_code / 摘要）。验收**确定性**：不靠 LLM 主观判断，只验签 + 比对
公告约定的 commit/command + acceptance 规则。

为什么这是好的第一个 SKU：Nth DAO 已有 execution receipt + 签名设施，
输入输出可绑定，验收争议最小（要么 commit/command 对得上、exit_code
达标，要么不）。

确定性 = 纯函数：``DeterministicTestVerifier.verify`` 不跑 sandbox、不碰
网络，只在 (公告, 交付的签名 receipt) 上算 pass/fail。worker 自己在
sandbox 跑、签 receipt；验收方只验证那张 receipt。（更强的"独立重跑"
stake-secured re-execution 留作未来可选项。）

输出喂给状态机：验收方拿 ``VerificationOutcome.verdict`` 调
``record_verification(store, trade_id, verifier=..., verdict=..., result=
outcome.checks)``。
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, Optional

from nth_dao.execution_receipt import TimelineEntry, now_ms, sign_receipt, verify_receipt
from nth_dao.market.announcement import TaskAnnouncement
from nth_dao.commerce.trade import VERDICT_FAIL, VERDICT_PASS

SKU_TEST_EXECUTION = "nth.test-execution.v1"
RECEIPT_TYPE_TEST_EXECUTION = "nth.test_execution"


@dataclass
class VerificationOutcome:
    """确定性验收结果 —— verdict + 可解释的逐项 checks。"""

    verdict: str                 # VERDICT_PASS / VERDICT_FAIL
    reason: str = ""             # fail 时的 machine-readable 首因
    checks: Dict[str, Any] = field(default_factory=dict)

    @property
    def passed(self) -> bool:
        return self.verdict == VERDICT_PASS


def sign_test_execution_receipt(
    worker: "Any",  # AgentIdentity（跑测试并签名的 worker）
    *,
    repository_url: str,
    commit: str,
    command: str,
    exit_code: int,
    stdout_digest: str = "",
    stderr_digest: str = "",
    environment_digest: str = "",
    announcement_id: str = "",
    now_ms_override: int = 0,
) -> Dict[str, Any]:
    """worker 跑完测试后产出一张签名 execution receipt（交付证据）。

    pin 的字段是验收要比对的：commit / command / exit_code + 摘要。
    """
    payload = {
        "sku": SKU_TEST_EXECUTION,
        "repository_url": repository_url,
        "commit": commit,
        "command": command,
        "exit_code": int(exit_code),
        "stdout_digest": stdout_digest,
        "stderr_digest": stderr_digest,
        "environment_digest": environment_digest,
        "announcement_id": announcement_id,
        "ran_at_ms": now_ms_override or now_ms(),
    }
    timeline = [
        TimelineEntry(
            timestamp=int(now_ms_override or now_ms()),
            type=RECEIPT_TYPE_TEST_EXECUTION,
            payload=payload,
        ),
    ]
    return sign_receipt(timeline, worker, goal_id=f"sku:{SKU_TEST_EXECUTION}")


def _test_execution_payload(receipt: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    timeline = receipt.get("timeline") if isinstance(receipt, dict) else None
    if not isinstance(timeline, list):
        return None
    for entry in timeline:
        if isinstance(entry, dict) and \
                entry.get("type") == RECEIPT_TYPE_TEST_EXECUTION:
            p = entry.get("payload")
            if isinstance(p, dict):
                return p
    return None


class DeterministicTestVerifier:
    """对 nth.test-execution.v1 的确定性验收。无状态、无副作用、可单测。"""

    sku = SKU_TEST_EXECUTION

    def verify(
        self,
        *,
        announcement: TaskAnnouncement,
        execution_receipt: Dict[str, Any],
        expected_signer_did: str,
    ) -> VerificationOutcome:
        """确定性算 pass/fail。

        Args:
            announcement: 公告。``input_schema`` 必须 pin ``commit`` +
                ``commands``（允许的命令列表）；``acceptance`` 可选
                ``accept_exit_codes``（默认 ``[0]``）。
            execution_receipt: 交付里 worker 签名的 execution receipt。
            expected_signer_did: 期望的签名者（= 该 trade 的 claimant/
                worker）。验收要确认 receipt 确实是这个 worker 签的。

        逐项 check（全过才 pass，任一 fail 即 fail，reason 记首因）：
          receipt_sig   —— verify_receipt 通过
          signer        —— receipt.signer_did == expected_signer_did
          payload       —— 含 nth.test_execution payload
          commit        —— payload.commit == announcement.input_schema.commit
          command       —— payload.command ∈ input_schema.commands
          exit_code     —— payload.exit_code ∈ acceptance.accept_exit_codes
        """
        checks: Dict[str, Any] = {}

        # 1. receipt 验签
        sig_ok = isinstance(execution_receipt, dict) and verify_receipt(execution_receipt)
        checks["receipt_sig"] = bool(sig_ok)
        if not sig_ok:
            return VerificationOutcome(VERDICT_FAIL, "receipt-sig-invalid", checks)

        # 2. signer 是期望的 worker
        signer = str(execution_receipt.get("signer_did", ""))
        signer_ok = signer == expected_signer_did
        checks["signer"] = signer_ok
        if not signer_ok:
            return VerificationOutcome(VERDICT_FAIL, "signer-mismatch", checks)

        # 3. 提取 test_execution payload
        payload = _test_execution_payload(execution_receipt)
        checks["payload"] = payload is not None
        if payload is None:
            return VerificationOutcome(VERDICT_FAIL, "no-test-execution-payload", checks)

        # 3.5 announcement 绑定（独立审查修复 CS2 R1）：receipt 必须 pin
        # 本公告的 announcement_id。否则同 commit+command 的两条公告里，
        # worker 跑一次、把同一张 receipt 复用到 N 条 → 一次活收 N 份钱。
        # 把 receipt 钉死到具体公告，杜绝 work-once-claim-many。
        want_ann = announcement.announcement_id
        got_ann = str(payload.get("announcement_id", ""))
        ann_ok = bool(want_ann) and got_ann == want_ann
        checks["announcement_id"] = ann_ok
        if not ann_ok:
            return VerificationOutcome(VERDICT_FAIL, "announcement-id-mismatch", checks)

        # 4. commit 比对
        want_commit = str((announcement.input_schema or {}).get("commit", ""))
        got_commit = str(payload.get("commit", ""))
        commit_ok = bool(want_commit) and got_commit == want_commit
        checks["commit"] = commit_ok
        if not commit_ok:
            return VerificationOutcome(VERDICT_FAIL, "commit-mismatch", checks)

        # 5. command 在允许列表内
        want_commands = (announcement.input_schema or {}).get("commands", [])
        got_command = str(payload.get("command", ""))
        command_ok = got_command in want_commands
        checks["command"] = command_ok
        if not command_ok:
            return VerificationOutcome(VERDICT_FAIL, "command-mismatch", checks)

        # 6. exit_code 达标
        accept_codes = (announcement.acceptance or {}).get("accept_exit_codes", [0])
        got_exit = payload.get("exit_code")
        exit_ok = isinstance(got_exit, int) and not isinstance(got_exit, bool) \
            and got_exit in accept_codes
        checks["exit_code"] = exit_ok
        if not exit_ok:
            return VerificationOutcome(VERDICT_FAIL, "exit-code-not-accepted", checks)

        return VerificationOutcome(VERDICT_PASS, "", checks)
