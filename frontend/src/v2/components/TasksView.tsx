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
import { useLang } from "../i18n";
import type { AgentEntry, TaskAnnouncement, TaskCategory } from "../types-v2";

export function TasksView() {
  const toast = useToast();
  const { t } = useLang();
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
          `${t("加载任务失败", "Failed to load tasks")}:${e instanceof Error ? e.message : String(e)}`,
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
      let r = await claimTask(annId, claimAgent);
      // 刚 spawn 的 agent 头一两秒还没轮询载入自己的 cap_token,认领会 401
      // not-yet-authorized。退避自动重试(最多 ~4s),省得让用户手动重点。
      for (let i = 0; i < 6; i++) {
        const isStartup =
          r.status === 401
          && JSON.stringify(r.body).includes("not-yet-authorized");
        if (!isStartup) break;
        await new Promise((res) => setTimeout(res, 700));
        r = await claimTask(annId, claimAgent);
      }
      const result = (r.body.result as Record<string, unknown>) || {};
      if (r.status === 200 && result.claimed) {
        toast.push(
          `${t("已认领 · 收据", "Claimed · receipt")} ${String(result.receipt_id || "").slice(0, 12)}…`,
          "success",
        );
        setReloadKey((k) => k + 1); // 任务离开广场
      } else {
        const err = (r.body.error as Record<string, unknown>) || {};
        const msg =
          err.message || r.body.detail || `HTTP ${r.status}`;
        toast.push(`${t("认领失败", "Claim failed")}:${String(msg)}`, "error");
      }
    } catch (e) {
      toast.push(
        `${t("认领失败", "Claim failed")}:${e instanceof Error ? e.message : String(e)}`,
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
      toast.push(t("任务已发布", "Task published"), "success");
      setFTitle("");
      setFCaps("");
      setFReward("");
      setFContext("");
      setFDesc("");
      setShowForm(false);
      setReloadKey((k) => k + 1); // 刷新任务 + 类别分面
    } catch (e) {
      toast.push(
        `${t("发布失败", "Publish failed")}:${e instanceof Error ? e.message : String(e)}`,
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
          <span className="sidebar-title">{t("类别", "Categories")}</span>
          <span className="sidebar-count">{cats.length}</span>
        </div>
        <div className="sidebar-list">
          <button
            className={`sidebar-item ${ctx === "" ? "active" : ""}`}
            onClick={() => setCtx("")}
          >
            <div className="sidebar-item-title">
              <span>{t("全部", "All")}</span>
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
            placeholder={t("按能力筛选 (如 code_review)", "Filter by capability (e.g. code_review)")}
            value={cap}
            onChange={(e) => setCap(e.target.value)}
          />
          <input
            placeholder={t("赏金下限", "Min reward")}
            inputMode="numeric"
            value={minReward}
            onChange={(e) => setMinReward(e.target.value.replace(/[^0-9]/g, ""))}
          />
          <input
            placeholder={t("搜索标题/详述", "Search title / description")}
            value={q}
            onChange={(e) => setQ(e.target.value)}
          />
          {/* 认领身份:选一个可驱动的 agent,它会用自己的私钥认领+签收据。 */}
          <label style={{ fontSize: 11, color: "var(--fg-tertiary)", marginTop: 4 }}>
            {t("认领身份", "Claim as")}
          </label>
          <select
            value={claimAgent}
            onChange={(e) => setClaimAgent(e.target.value)}
            disabled={agents.length === 0}
          >
            <option value="">
              {agents.length
                ? t("选择认领 agent", "Select claiming agent")
                : t("无可用 agent(先 spawn)", "No agent available (spawn one first)")}
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
            <p className="main-eyebrow">
              {t("任务广场 · 发现可认领的活", "Task market · discover claimable work")}
            </p>
            <h1 className="main-title">Tasks {loading ? "…" : `(${tasks.length})`}</h1>
          </div>
          <button className="btn btn-primary" onClick={() => setShowForm((s) => !s)}>
            {showForm ? t("取消", "Cancel") : t("+ 发布任务", "+ Publish task")}
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
                placeholder={t("任务标题 *", "Task title *")}
                value={fTitle}
                maxLength={200}
                onChange={(e) => setFTitle(e.target.value)}
              />
              <input
                placeholder={t("所需能力,逗号分隔 (如 code_review, research)", "Required capabilities, comma-separated (e.g. code_review, research)")}
                value={fCaps}
                onChange={(e) => setFCaps(e.target.value)}
              />
              <div style={{ display: "flex", gap: 8 }}>
                <input
                  placeholder={t("类别 (context)", "Category (context)")}
                  value={fContext}
                  onChange={(e) => setFContext(e.target.value)}
                  style={{ flex: 1 }}
                />
                <input
                  placeholder={t("赏金 (整数)", "Reward (integer)")}
                  inputMode="numeric"
                  value={fReward}
                  onChange={(e) => setFReward(e.target.value.replace(/[^0-9]/g, ""))}
                  style={{ width: 120 }}
                />
              </div>
              <textarea
                placeholder={t("任务详述", "Task description")}
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
                {publishing ? t("发布中…", "Publishing…") : t("发布", "Publish")}
              </button>
            </form>
          )}

          {tasks.length === 0 ? (
            <div className="main-empty" style={{ minHeight: 200 }}>
              <div className="main-empty-icon">
                <IconBriefcase size={36} />
              </div>
              <p>{t("没有匹配的开放任务。", "No matching open tasks.")}</p>
              <p className="muted" style={{ fontSize: 12, marginTop: 4 }}>
                {t("换个筛选,或发布一条任务。", "Adjust filters, or publish a task.")}
              </p>
            </div>
          ) : (
            <div className="stack" style={{ gap: 10 }}>
              {tasks.map((task) => (
                <article
                  key={task.announcement_id}
                  style={{
                    border: "1px solid var(--border)",
                    borderRadius: "var(--r-md)",
                    padding: "12px 14px",
                    background: "var(--bg-panel)",
                  }}
                >
                  <div style={{ display: "flex", alignItems: "baseline", gap: 8 }}>
                    <strong style={{ fontSize: 14 }}>{task.title}</strong>
                    {task.context && (
                      <span className="pill dim" style={{ fontSize: 10 }}>
                        {task.context}
                      </span>
                    )}
                    {task.federated && (
                      <span
                        className="pill"
                        title={t(
                          `来自对端 DAO:${task.source_peer || ""}`,
                          `From peer DAO: ${task.source_peer || ""}`,
                        )}
                        style={{
                          fontSize: 10,
                          color: "var(--accent)",
                          borderColor: "var(--accent-muted)",
                        }}
                      >
                        {t("联邦", "federated")}
                      </span>
                    )}
                    {task.reward_minor > 0 && (
                      <span
                        style={{
                          marginLeft: "auto",
                          color: "var(--accent)",
                          fontSize: 13,
                          fontWeight: 500,
                        }}
                      >
                        {task.reward_minor} {task.reward_asset}
                      </span>
                    )}
                  </div>
                  {task.description && (
                    <p
                      style={{
                        margin: "6px 0 0",
                        fontSize: 13,
                        color: "var(--fg-secondary)",
                      }}
                    >
                      {task.description}
                    </p>
                  )}
                  {task.capability_set.length > 0 && (
                    <div
                      style={{ display: "flex", flexWrap: "wrap", gap: 6, marginTop: 8 }}
                    >
                      {task.capability_set.map((c) => (
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
                      {t("发布者", "By")} {task.publisher_did.slice(0, 18)}…
                      {task.published_at_ms
                        ? ` · ${relativeTimeShort(new Date(task.published_at_ms).toISOString())}`
                        : ""}
                    </span>
                    {/* 认领:用左栏所选 agent,由 agent 自己私钥签收据。 */}
                    <button
                      className="btn"
                      disabled={
                        !claimAgent
                        || claimingId === task.announcement_id
                        || !!task.federated
                      }
                      title={
                        task.federated
                          ? t(
                              "联邦任务的认领需在来源 DAO 进行(本地无认领权威)",
                              "Federated tasks must be claimed at their source DAO (no local claim authority)",
                            )
                          : claimAgent
                            ? t("用所选 agent 认领(agent 自签收据)", "Claim with selected agent (agent self-signs the receipt)")
                            : t("先在左栏选一个认领 agent", "Pick a claiming agent in the left panel first")
                      }
                      style={{ marginLeft: "auto" }}
                      onClick={() => void handleClaim(task.announcement_id)}
                    >
                      {claimingId === task.announcement_id
                        ? t("认领中…", "Claiming…")
                        : task.federated
                          ? t("源端认领", "at source")
                          : t("认领", "Claim")}
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
