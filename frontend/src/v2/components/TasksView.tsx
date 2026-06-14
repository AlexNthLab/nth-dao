/**
 * TasksView — 任务广场(发现态)。A2A 协调底座的核心面:发现可认领的活。
 *
 * 左栏:类别分面(context)+ 能力/赏金/搜索筛选。
 * 主区:发布表单(+ 发布任务)+ 公告卡片列表(标题/类别/能力/赏金/发布者)。
 * 认领按钮先占位禁用——认领是跨进程(切片B),由 agent 自己用私钥签。
 *
 * 自取数(import api),不经 App 状态,保持视图自洽。
 */
import { useEffect, useState } from "react";
import {
  announceTask, claimTask, fetchAgents, listOpenTasks, listTaskCategories,
} from "../api";
import { IconBriefcase } from "./Icons";
import { useToast } from "./Toast";
import { relativeTimeShort } from "../utils/time";
import type { AgentEntry, TaskAnnouncement, TaskCategory } from "../types-v2";

export function TasksView() {
  const toast = useToast();
  const [tasks, setTasks] = useState<TaskAnnouncement[]>([]);
  const [cats, setCats] = useState<TaskCategory[]>([]);
  const [loading, setLoading] = useState(false);

  // 筛选
  const [ctx, setCtx] = useState("");
  const [cap, setCap] = useState("");
  const [minReward, setMinReward] = useState("");
  const [q, setQ] = useState("");

  // 发布表单
  const [showForm, setShowForm] = useState(false);
  const [fTitle, setFTitle] = useState("");
  const [fCaps, setFCaps] = useState("");
  const [fReward, setFReward] = useState("");
  const [fContext, setFContext] = useState("");
  const [fDesc, setFDesc] = useState("");
  const [publishing, setPublishing] = useState(false);
  // 发布/认领后 bump,触发任务 + 类别 + agent 列表一起刷新(否则筛选没变,
  // 任务 effect 不会重跑,新发/已认领的任务状态看不见)。
  const [reloadKey, setReloadKey] = useState(0);

  // 认领:可驱动的 supervised agent + 当前选中的认领身份(按 DID)。
  const [agents, setAgents] = useState<AgentEntry[]>([]);
  const [claimAgent, setClaimAgent] = useState("");
  const [claimingId, setClaimingId] = useState("");

  async function loadTasks(signal?: AbortSignal) {
    setLoading(true);
    try {
      const t = await listOpenTasks(
        {
          context: ctx,
          capability: cap,
          minReward: minReward ? Number(minReward) : 0,
          q,
        },
        signal,
      );
      setTasks(t);
    } catch (e) {
      if (!(e instanceof DOMException && e.name === "AbortError")) {
        toast.push(
          `加载任务失败:${e instanceof Error ? e.message : String(e)}`,
          "error",
        );
      }
    } finally {
      setLoading(false);
    }
  }

  async function loadCategories(signal?: AbortSignal) {
    try {
      setCats(await listTaskCategories(signal));
    } catch {
      // 分面是锦上添花,失败静默(不打断浏览)。
    }
  }

  // 任务:筛选变化(文本防抖 300ms,避免逐键刷屏)或发布后(reloadKey)重拉。
  // AbortController 取消上一笔,防乱序覆盖。
  useEffect(() => {
    const ac = new AbortController();
    const timer = setTimeout(() => void loadTasks(ac.signal), 300);
    return () => {
      clearTimeout(timer);
      ac.abort();
    };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [ctx, cap, minReward, q, reloadKey]);

  // 类别分面是全局 facet(不随筛选变),只在挂载 + 发布后刷新。
  useEffect(() => {
    const ac = new AbortController();
    void loadCategories(ac.signal);
    return () => ac.abort();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [reloadKey]);

  // 可认领身份:拉可驱动的 supervised agent(supervised+alive+有 a2a_port)。
  useEffect(() => {
    const ac = new AbortController();
    fetchAgents(ac.signal)
      .then((all) => {
        const drivable = all.filter(
          (a) => a.supervised && a.alive && a.a2a_port != null,
        );
        setAgents(drivable);
        setClaimAgent((cur) => cur || drivable[0]?.did || "");
      })
      .catch(() => {
        /* agent 列表拉取失败不打断浏览 */
      });
    return () => ac.abort();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [reloadKey]);

  async function handleClaim(annId: string) {
    if (!claimAgent || claimingId) return;
    setClaimingId(annId);
    try {
      const res = await claimTask(annId, claimAgent);
      const result = (res.result as Record<string, unknown>) || {};
      if (result.claimed) {
        toast.push(
          `已认领 · 收据 ${String(result.receipt_id || "").slice(0, 12)}…`,
          "success",
        );
        setReloadKey((k) => k + 1); // 任务离开广场
      } else {
        toast.push("认领未成功", "error");
      }
    } catch (e) {
      toast.push(
        `认领失败:${e instanceof Error ? e.message : String(e)}`,
        "error",
      );
    } finally {
      setClaimingId("");
    }
  }

  async function handlePublish(e: React.FormEvent) {
    e.preventDefault();
    if (!fTitle.trim() || publishing) return;
    setPublishing(true);
    try {
      await announceTask({
        title: fTitle.trim(),
        capability_set: fCaps
          .split(",")
          .map((s) => s.trim())
          .filter(Boolean),
        reward_minor: fReward ? Math.max(0, Math.floor(Number(fReward))) : 0,
        context: fContext.trim(),
        description: fDesc.trim(),
      });
      toast.push("任务已发布", "success");
      setFTitle("");
      setFCaps("");
      setFReward("");
      setFContext("");
      setFDesc("");
      setShowForm(false);
      setReloadKey((k) => k + 1); // 刷新任务 + 类别分面
    } catch (e) {
      toast.push(
        `发布失败:${e instanceof Error ? e.message : String(e)}`,
        "error",
      );
    } finally {
      setPublishing(false);
    }
  }

  return (
    <>
      <aside className="sidebar">
        <div className="sidebar-head">
          <span className="sidebar-title">类别</span>
          <span className="sidebar-count">{cats.length}</span>
        </div>
        <div className="sidebar-list">
          <button
            className={`sidebar-item ${ctx === "" ? "active" : ""}`}
            onClick={() => setCtx("")}
          >
            <div className="sidebar-item-title">
              <span>全部</span>
            </div>
          </button>
          {cats.map((c) => (
            <button
              key={c.context}
              className={`sidebar-item ${ctx === c.context ? "active" : ""}`}
              onClick={() => setCtx(c.context)}
            >
              <div className="sidebar-item-title">
                <span className="truncate">{c.context}</span>
                <span className="pill dim" style={{ marginLeft: "auto", fontSize: 10 }}>
                  {c.count}
                </span>
              </div>
            </button>
          ))}
        </div>
        <div
          style={{
            padding: "10px 12px",
            borderTop: "1px solid var(--border)",
            display: "flex",
            flexDirection: "column",
            gap: 8,
          }}
        >
          <input
            placeholder="按能力筛选 (如 code_review)"
            value={cap}
            onChange={(e) => setCap(e.target.value)}
          />
          <input
            placeholder="赏金下限"
            inputMode="numeric"
            value={minReward}
            onChange={(e) => setMinReward(e.target.value.replace(/[^0-9]/g, ""))}
          />
          <input
            placeholder="搜索标题/详述"
            value={q}
            onChange={(e) => setQ(e.target.value)}
          />
          {/* 认领身份:选一个可驱动的 agent,它会用自己的私钥认领+签收据。 */}
          <label style={{ fontSize: 11, color: "var(--fg-tertiary)", marginTop: 4 }}>
            认领身份
          </label>
          <select
            value={claimAgent}
            onChange={(e) => setClaimAgent(e.target.value)}
            disabled={agents.length === 0}
          >
            <option value="">
              {agents.length ? "选择认领 agent" : "无可用 agent(先 spawn)"}
            </option>
            {agents.map((a) => (
              <option key={a.did} value={a.did}>
                {a.label} ({a.did.slice(0, 12)}…)
              </option>
            ))}
          </select>
        </div>
      </aside>

      <section className="main" style={{ display: "flex", flexDirection: "column" }}>
        <div
          className="main-head"
          style={{
            position: "static",
            display: "flex",
            alignItems: "center",
            justifyContent: "space-between",
          }}
        >
          <div>
            <p className="main-eyebrow">任务广场 · 发现可认领的活</p>
            <h1 className="main-title">Tasks {loading ? "…" : `(${tasks.length})`}</h1>
          </div>
          <button className="btn btn-primary" onClick={() => setShowForm((s) => !s)}>
            {showForm ? "取消" : "+ 发布任务"}
          </button>
        </div>

        <div style={{ flex: 1, overflowY: "auto", padding: "16px 24px" }}>
          {showForm && (
            <form
              onSubmit={handlePublish}
              style={{
                border: "1px solid var(--border)",
                borderRadius: "var(--r-md)",
                padding: 14,
                marginBottom: 16,
                display: "flex",
                flexDirection: "column",
                gap: 8,
              }}
            >
              <input
                placeholder="任务标题 *"
                value={fTitle}
                maxLength={200}
                onChange={(e) => setFTitle(e.target.value)}
              />
              <input
                placeholder="所需能力,逗号分隔 (如 code_review, research)"
                value={fCaps}
                onChange={(e) => setFCaps(e.target.value)}
              />
              <div style={{ display: "flex", gap: 8 }}>
                <input
                  placeholder="类别 (context)"
                  value={fContext}
                  onChange={(e) => setFContext(e.target.value)}
                  style={{ flex: 1 }}
                />
                <input
                  placeholder="赏金 (整数)"
                  inputMode="numeric"
                  value={fReward}
                  onChange={(e) => setFReward(e.target.value.replace(/[^0-9]/g, ""))}
                  style={{ width: 120 }}
                />
              </div>
              <textarea
                placeholder="任务详述"
                value={fDesc}
                maxLength={4000}
                onChange={(e) => setFDesc(e.target.value)}
                style={{ minHeight: 60 }}
              />
              <button
                type="submit"
                className="btn btn-primary"
                disabled={!fTitle.trim() || publishing}
                style={{ alignSelf: "flex-start" }}
              >
                {publishing ? "发布中…" : "发布"}
              </button>
            </form>
          )}

          {tasks.length === 0 ? (
            <div className="main-empty" style={{ minHeight: 200 }}>
              <div className="main-empty-icon">
                <IconBriefcase size={36} />
              </div>
              <p>没有匹配的开放任务。</p>
              <p className="muted" style={{ fontSize: 12, marginTop: 4 }}>
                换个筛选,或发布一条任务。
              </p>
            </div>
          ) : (
            <div className="stack" style={{ gap: 10 }}>
              {tasks.map((t) => (
                <article
                  key={t.announcement_id}
                  style={{
                    border: "1px solid var(--border)",
                    borderRadius: "var(--r-md)",
                    padding: "12px 14px",
                    background: "var(--bg-panel)",
                  }}
                >
                  <div style={{ display: "flex", alignItems: "baseline", gap: 8 }}>
                    <strong style={{ fontSize: 14 }}>{t.title}</strong>
                    {t.context && (
                      <span className="pill dim" style={{ fontSize: 10 }}>
                        {t.context}
                      </span>
                    )}
                    {t.reward_minor > 0 && (
                      <span
                        style={{
                          marginLeft: "auto",
                          color: "var(--accent)",
                          fontSize: 13,
                          fontWeight: 500,
                        }}
                      >
                        {t.reward_minor} {t.reward_asset}
                      </span>
                    )}
                  </div>
                  {t.description && (
                    <p
                      style={{
                        margin: "6px 0 0",
                        fontSize: 13,
                        color: "var(--fg-secondary)",
                      }}
                    >
                      {t.description}
                    </p>
                  )}
                  {t.capability_set.length > 0 && (
                    <div
                      style={{ display: "flex", flexWrap: "wrap", gap: 6, marginTop: 8 }}
                    >
                      {t.capability_set.map((c) => (
                        <span key={c} className="pill dim" style={{ fontSize: 10 }}>
                          {c}
                        </span>
                      ))}
                    </div>
                  )}
                  <div
                    style={{
                      marginTop: 8,
                      display: "flex",
                      alignItems: "center",
                      fontSize: 11,
                      color: "var(--fg-tertiary)",
                      fontFamily: "var(--t-mono)",
                    }}
                  >
                    <span>
                      发布者 {t.publisher_did.slice(0, 18)}…
                      {t.published_at_ms
                        ? ` · ${relativeTimeShort(new Date(t.published_at_ms).toISOString())}`
                        : ""}
                    </span>
                    {/* 认领:用左栏所选 agent,由 agent 自己私钥签收据。 */}
                    <button
                      className="btn"
                      disabled={!claimAgent || claimingId === t.announcement_id}
                      title={
                        claimAgent
                          ? "用所选 agent 认领(agent 自签收据)"
                          : "先在左栏选一个认领 agent"
                      }
                      style={{ marginLeft: "auto" }}
                      onClick={() => void handleClaim(t.announcement_id)}
                    >
                      {claimingId === t.announcement_id ? "认领中…" : "认领"}
                    </button>
                  </div>
                </article>
              ))}
            </div>
          )}
        </div>
      </section>
    </>
  );
}
