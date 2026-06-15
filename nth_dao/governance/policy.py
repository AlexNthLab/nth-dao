"""声明式治理策略 —— 一个 DAO 的"宪法"数据模型(Phase 4)。

一份 Policy 用**声明式**(纯数据)描述:谁是什么角色、各角色被授予哪些动作、
某些动作的约束(额度上限 / 法定人数)。引擎(``engine.py``)对它做**确定性、
无 I/O、无 wall-clock** 的评估 → 跨节点一致(同输入必同判定)。

  - ``roles``       did → [role]              谁是什么角色
  - ``grants``      role → [action pattern]   角色被授予的动作(支持 ``a.*`` / ``*``)
  - ``constraints`` action → {约束}            如 {"max_minor": 1000} / {"quorum": {...}}

策略本身是配置;把"策略修订"做成 spine 的 governance 事件 + 投影是 Phase 4b。
canonical_json 友好(无 float),便于签名 / 上链统一日志。
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, List, Set


@dataclass
class Policy:
    roles: Dict[str, List[str]] = field(default_factory=dict)
    grants: Dict[str, List[str]] = field(default_factory=dict)
    constraints: Dict[str, Dict[str, Any]] = field(default_factory=dict)

    def roles_of(self, did: str) -> Set[str]:
        """``did`` 持有的角色集合(去重)。未登记 → 空集。"""
        return set(self.roles.get(did, []) or [])

    def to_dict(self) -> Dict[str, Any]:
        return {
            "roles": {k: sorted(set(v)) for k, v in self.roles.items()},
            "grants": {k: sorted(set(v)) for k, v in self.grants.items()},
            "constraints": dict(self.constraints),
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "Policy":
        if not isinstance(data, dict):
            raise TypeError("policy must be a dict")

        def _str_list_map(raw: Any) -> Dict[str, List[str]]:
            out: Dict[str, List[str]] = {}
            for k, v in (raw or {}).items():
                if not isinstance(k, str) or not isinstance(v, list):
                    raise TypeError(f"policy map {k!r} must be str→list")
                out[k] = [str(x) for x in v]
            return out

        constraints_raw = data.get("constraints") or {}
        if not isinstance(constraints_raw, dict):
            raise TypeError("constraints must be a dict")
        constraints: Dict[str, Dict[str, Any]] = {}
        for action, c in constraints_raw.items():
            if not isinstance(action, str) or not isinstance(c, dict):
                raise TypeError("constraints must be action(str)→dict")
            constraints[action] = dict(c)

        return cls(
            roles=_str_list_map(data.get("roles")),
            grants=_str_list_map(data.get("grants")),
            constraints=constraints,
        )
