"""投影 —— 把事件流折叠成物化视图(Phase 1)。

spine 是唯一事实源;market 开放公告、账本余额、成员名册、信誉、审计时间线
等都是对事件流的 reduce 结果。``Projection`` 子类实现 ``apply(event)``;``replay``
在调用方已 ``verify_chain`` 后,把全量事件按序喂进去重建视图。

这是后续 Phase 把现有 feed 迁成"视图"的接口:每个旧 feed 退化成一个
Projection,读路径切到投影结果,写路径改为向 spine append 事件。
"""
from __future__ import annotations

from typing import Iterable

from nth_dao.spine.event import SpineEvent


class Projection:
    """投影基类:按事件类型增量折叠出一个物化视图。"""

    def apply(self, event: SpineEvent) -> None:
        raise NotImplementedError

    def reset(self) -> None:
        """重建前清空内部状态(默认无状态;有状态的子类覆盖)。"""


def replay(events: Iterable[SpineEvent], *projections: Projection) -> None:
    """把事件按序喂给每个投影。调用方负责已对来源 ``verify_chain``。"""
    for ev in events:
        for p in projections:
            p.apply(ev)
