"""市场技能词表（约束 A：发布方与 Agent 共享同一套能力名）。

为什么需要词表：主动市场的匹配是"公告所需能力 ⊆ Agent 声明能力"的
集合判定（见 ``match.py``）。若双方用不一致的写法（``code_review`` /
``CodeReview`` / ``code review`` / ``code-review``），集合判定永远不
命中 —— 这是 C3"精确字符串匹配"问题的根。词表给出**规范化函数**让
两边都收敛到同一形式。

与 ``cap_token`` 的 ``KNOWN_CAPABILITIES`` 的区别：
  - cap_token 的能力是**协议能力**（你能调哪个 A2A 方法）：
    ``a2a:message_send`` / ``nth:receipt_sign`` …
  - 市场技能是**劳务能力**（你能干哪种活）：
    ``code_review`` / ``test_execution`` / ``research`` …
  两者命名空间不同、用途不同，故分开。市场技能用裸小写标识符，与
  ``marketplace.TaskOrder.context`` 既有取值（code_review / bug_fix /
  research / write_docs / deploy）保持一致。

开放性设计：市场要让全世界 Agent 都能发布/发现任务，所以词表**不是
封闭白名单** —— ``normalize_capability`` 接受任何良构标识符，
``is_known_skill`` 只是给 UI 一个"这是不是公认技能"的提示，匹配本身
不要求技能在册。这样既有规范化（避免 typo 不命中），又不挡住新技能。
"""

from __future__ import annotations

import re
from typing import Tuple

# ── 公认技能（canonical 名，与 marketplace context 取值对齐）──

SKILL_CODE_REVIEW = "code_review"
SKILL_BUG_FIX = "bug_fix"
SKILL_TEST_EXECUTION = "test_execution"      # 对应交易路线图 SKU 1
SKILL_STATIC_ANALYSIS = "static_analysis"    # 对应交易路线图 SKU 2
SKILL_RESEARCH = "research"                  # 对应交易路线图 SKU 3
SKILL_WRITE_DOCS = "write_docs"
SKILL_DEPLOY = "deploy"
SKILL_TRANSLATION = "translation"
SKILL_DATA_LABELING = "data_labeling"
SKILL_SUMMARIZE = "summarize"

KNOWN_SKILLS = frozenset({
    SKILL_CODE_REVIEW,
    SKILL_BUG_FIX,
    SKILL_TEST_EXECUTION,
    SKILL_STATIC_ANALYSIS,
    SKILL_RESEARCH,
    SKILL_WRITE_DOCS,
    SKILL_DEPLOY,
    SKILL_TRANSLATION,
    SKILL_DATA_LABELING,
    SKILL_SUMMARIZE,
})

# 良构能力标识符：小写字母/数字/下划线，1-64 字符。
# 不允许冒号 —— 冒号是协议能力（cap_token）的命名空间分隔，市场技能
# 不用它，避免两套命名空间混淆。
_CAP_RE = re.compile(r"^[a-z0-9_]{1,64}$")

REJECT_CAP_EMPTY = "capability-empty"
REJECT_CAP_BAD_SHAPE = "capability-bad-shape"


def normalize_capability(raw: str) -> str:
    """把一个能力名收敛到规范形式：strip + 小写 + 内部空白/连字符折叠
    为下划线。

    例：
      "  Code Review " -> "code_review"
      "bug-fix"        -> "bug_fix"
      "RESEARCH"       -> "research"

    规范化只做"明显等价"的折叠，不做语义猜测（不会把 "review" 映射到
    "code_review"）。返回值可能仍不是良构（比如含非法字符），由
    ``validate_capability`` 判定。
    """
    if not isinstance(raw, str):
        return ""
    s = raw.strip().lower()
    # 连字符 + 任意空白 → 下划线；多个下划线折叠为一个
    s = re.sub(r"[\s\-]+", "_", s)
    s = re.sub(r"_+", "_", s).strip("_")
    return s


def validate_capability(raw: str) -> Tuple[bool, str]:
    """检查能力名是否良构（规范化后符合 ``^[a-z0-9_]{1,64}$``）。

    Returns ``(ok, reason)``；ok=True 时 reason 为 ""。
    """
    norm = normalize_capability(raw)
    if not norm:
        return False, REJECT_CAP_EMPTY
    if not _CAP_RE.match(norm):
        return False, REJECT_CAP_BAD_SHAPE
    return True, ""


def is_known_skill(cap: str) -> bool:
    """规范化后是否在公认技能集里。仅供 UI 提示，匹配不依赖它。"""
    return normalize_capability(cap) in KNOWN_SKILLS
