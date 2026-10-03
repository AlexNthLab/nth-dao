/**
 * TasksView — 任务广场(发现态)。A2A 协调底座的核心面:发现可认领的活。
 *
 * 左栏:类别分面(context)+ 能力/赏金/搜索筛选。
 * 主区:公告卡片列表(标题/类别/能力/赏金/发布者)。
 * 认领按钮先占位禁用——认领是跨进程(切片B),由 agent 自己用私钥签。
 *
 * 自取数(import api),不经 App 状态,保持视图自洽。
 */
import { useEffect, useState } from "react";
import {
  claimFederatedTask, claimTask, fetchAgents, listClaimIntents, listOpenTasks,
  listTaskCategories, reconcileClaimIntent,
} from "../api";
import { IconBriefcase } from "./Icons";
import { useToast } from "./Toast";
import { relativeTimeShort } from "../utils/time";
import { useLang } from "../i18n";
import type {
  AgentEntry,
  ClaimIntentRecord,
  TaskAnnouncement,
  TaskCategory,
} from "../types-v2";

function visibilityWarningLabel(
  code: string,
  t: (zh: string, en: string) => string,
): string {
  switch (code) {
    case "mission_visibility_failed":
      return t("Mission 执行视图写入失败", "Mission execution view failed to persist");
    case "blackboard_visibility_failed":
      return t("Blackboard 协作现场写入失败", "Blackboard collaboration view failed to persist");
    default:
      if (code.startsWith("linked_mission_")) {
        return t("关联 Mission 同步失败", "Linked Mission sync failed");
      }
      return t("执行视图写入异常", "Execution view persistence warning");
  }
}

interface TasksViewProps {
  onOpenPublisher?: () => void;
}

export function TasksView({ onOpenPublisher }: TasksViewProps) {
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

  // 市场化分区 + 排序。market=可承接的活(本节点+联邦);mine=我发布的。
  const [tab, setTab] = useState<"market" | "mine" | "claims">("market");
  const [sort, setSort] = useState<"recent" | "reward">("recent");

  // 认领后 bump,触发任务 + agent 列表一起刷新。
  const [reloadKey, setReloadKey] = useState(0);

  // 认领:可驱动的 supervised agent + 当前选中的认领身份(按 DID)。
  const [agents, setAgents] = useState<AgentEntry[]>([]);
  const [claimAgent, setClaimAgent] = useState("");
  const [claimingId, setClaimingId] = useState("");
  const [claimIntents, setClaimIntents] = useState<ClaimIntentRecord[]>([]);
  const [claimIntentError, setClaimIntentError] = useState("");
  const [claimIntentVersion, setClaimIntentVersion] = useState(0);
  const [reconcilingNonce, setReconcilingNonce] = useState("");

  // 我发布的 = 本节点 feed(非联邦);市场 = 全部(可承接)。按所选维度排序。
  const myTasks = tasks.filter((x) => !x.federated);
  const shown = [...(tab === "mine" ? myTasks : tasks)].sort((a, b) =>
    sort === "reward"
      ? (b.reward_minor || 0) - (a.reward_minor || 0)
      : (b.published_at_ms || 0) - (a.published_at_ms || 0),
  );

  async function loadTasks(signal?: AbortSignal) {
    setLoading(true);
    try {
      const t = await listOpenTasks(
        {
          context: ctx,
          capability: cap,
          listingType: "task",
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
      setCats(await listTaskCategories("task", signal));
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

  useEffect(() => {
    const ac = new AbortController();
    listClaimIntents(100, ac.signal)
      .then((page) => {
        setClaimIntents(page.items);
        setClaimIntentError("");
      })
      .catch((error) => {
        if (!(error instanceof DOMException && error.name === "AbortError")) {
          setClaimIntentError(error instanceof Error ? error.message : String(error));
        }
      });
    return () => ac.abort();
  }, [claimIntentVersion]);

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

  async function handleClaim(task: TaskAnnouncement) {
    if ((task.listing_type || "task") !== "task" || task.claimable === false) {
      toast.push(
        "This entry is not a claimable Task. Open it from Market instead.",
        "info",
      );
      return;
    }
    const annId = task.announcement_id;
    if (!claimAgent || claimingId) return;
    setClaimingId(annId);
    const doClaim = () =>
      task.federated
        ? claimFederatedTask(annId, claimAgent, task.federation_key || "")
        : claimTask(annId, claimAgent);
    try {
      let r = await doClaim();
      // 刚 spawn 的 agent 头一两秒还没轮询载入自己的 cap_token,认领会 401
      // not-yet-authorized。退避自动重试(最多 ~4s),省得让用户手动重点。
      for (let i = 0; i < 6; i++) {
        const isStartup =
          r.status === 401
          && JSON.stringify(r.body).includes("not-yet-authorized");
        if (!isStartup) break;
        await new Promise((res) => setTimeout(res, 700));
        r = await doClaim();
      }
      // 本地 claim 回 {result:{claimed,receipt_id}};跨 DAO claim-foreign 回
      // {claimed,receipt_id,...} 直挂在 body。两种都认。
      const result =
        (r.body.result as Record<string, unknown>) || r.body;
      if (r.status === 200 && result.claimed) {
        const reconciled = Boolean(result.reconciled_intent_nonce);
        const alreadyConfirmed = Boolean(result.already_confirmed_intent_nonce);
        const missionHint = result.mission_id
          ? ` · ${t("已进入 Missions", "now in Missions")} ${String(result.mission_id).slice(0, 12)}…`
          : "";
        const visibilityStatus = String(result.visibility_status || "ok");
        const warnings = Array.isArray(result.visibility_warnings)
          ? Array.from(new Set(result.visibility_warnings.map(String).filter(Boolean)))
          : [];
        const warningText = warnings
          .map((warning) => visibilityWarningLabel(warning, t))
          .join(" · ");
        const receiptText = `${t("已认领 · 收据", "Claimed · receipt")} ${String(result.receipt_id || "").slice(0, 12)}…${missionHint}`;
        if (reconciled) {
          toast.push(
            t(
              "之前待确认的认领已获来源 DAO 确认;本次重试意图未被接受。",
              "A prior pending claim was confirmed by the source DAO; this retry intent was not accepted.",
            ),
            "success",
          );
        } else if (alreadyConfirmed) {
          toast.push(
            t(
              "该 Agent 已持有此认领;本次重复意图未被接受。",
              "This Agent already holds the claim; the duplicate intent was not accepted.",
            ),
            "info",
          );
        } else if (visibilityStatus === "ok") {
          toast.push(receiptText, "success");
        } else {
          toast.push(
            `${receiptText} · ${t("执行视图未完全写入", "execution view not fully persisted")}${warningText ? `: ${warningText}` : ""}`,
            "warn",
          );
        }
        setReloadKey((k) => k + 1); // 任务离开广场
      } else if (result.claim_intent_state === "pending") {
        const err = (r.body.error as Record<string, unknown>) || {};
        toast.push(
          `${t("认领意图已保存,等待来源 DAO 确认", "Claim intent saved; source confirmation is pending")}: ${String(err.message || `HTTP ${r.status}`)}`,
          "warn",
        );
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
      if (task.federated) setClaimIntentVersion((version) => version + 1);
    }
  }

  async function handleReconcile(record: ClaimIntentRecord) {
    const nonce = record.intent.nonce;
    if (reconcilingNonce) return;
    setReconcilingNonce(nonce);
    try {
      const result = await reconcileClaimIntent(nonce);
      if (result.status === 200 && result.body.state === "confirmed") {
        toast.push(
          t(
            "来源 DAO 已确认该认领,权威回执已保存。",
            "The source DAO confirmed this claim and its authority ACK was saved.",
          ),
          "success",
        );
        setClaimIntentVersion((version) => version + 1);
      } else if (result.status === 200 && result.body.state !== "confirmed") {
        toast.push(
          t(
            "来源 DAO 未返回可验证的认领确认,本地状态保持不变。",
            "The source DAO returned no verifiable claim confirmation; local state is unchanged.",
          ),
          "warn",
        );
      } else {
        const error = result.body.error as Record<string, unknown> | undefined;
        const message = error?.message || result.body.detail || `HTTP ${result.status}`;
        toast.push(
          `${t("恢复认领状态失败", "Claim reconciliation failed")}: ${String(message)}`,
          "error",
        );
      }
    } catch (error) {
      toast.push(
        `${t("恢复认领状态失败", "Claim reconciliation failed")}: ${error instanceof Error ? error.message : String(error)}`,
        "error",
      );
    } finally {
      setReconcilingNonce("");
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
              Task work queue
            </p>
            <h1 className="main-title">Tasks {loading ? "…" : `(${tab === "claims" ? claimIntents.length : shown.length})`}</h1>
            <p className="main-subtitle">
              {t(
                "查看和承接外部工作。认领成功后会进入 Missions 执行,并在 Blackboard 显示状态。",
                "Review and claim work requests. A claim creates or links a Mission and exposes execution on the Blackboard.",
              )}
            </p>
          </div>
          <button className="btn btn-primary" type="button" onClick={onOpenPublisher}>
            {t("前往市场发布", "Publish in Market")}
          </button>
        </div>

        <div style={{ flex: 1, overflowY: "auto", padding: "16px 24px" }}>
          {/* 市场分区(可承接 vs 我发布的)+ 排序 */}
          <div
            style={{
              display: "flex", alignItems: "center", gap: 10,
              marginBottom: 14, flexWrap: "wrap",
            }}
          >
            <button
              className={`btn ${tab === "market" ? "btn-primary" : "btn-ghost"}`}
              style={{ fontSize: 12 }}
              onClick={() => setTab("market")}
              title={t("各 DAO 发布的、可承接的活(含联邦)", "Claimable work from across DAOs (incl. federated)")}
            >
              Available ({tasks.length})
            </button>
            <button
              className={`btn ${tab === "mine" ? "btn-primary" : "btn-ghost"}`}
              style={{ fontSize: 12 }}
              onClick={() => setTab("mine")}
              title={t("本节点发布、供他人认领的活", "Tasks this DAO published for others to claim")}
            >
              {t("我发布的", "My published")} ({myTasks.length})
            </button>
            <button
              className={`btn ${tab === "claims" ? "btn-primary" : "btn-ghost"}`}
              style={{ fontSize: 12 }}
              onClick={() => setTab("claims")}
            >
              {t("我的认领", "My claims")} ({claimIntents.length})
            </button>
            <span style={{ flex: 1 }} />
            {tab !== "claims" && <label
              className="muted"
              style={{ fontSize: 12, display: "flex", alignItems: "center", gap: 6 }}
            >
              {t("排序", "Sort")}
              <select
                value={sort}
                onChange={(e) => setSort(e.target.value as "recent" | "reward")}
              >
                <option value="recent">{t("最新", "Newest")}</option>
                <option value="reward">{t("赏金高→低", "Reward ↓")}</option>
              </select>
            </label>}
          </div>

          {tab === "claims" ? (
            <div className="stack" style={{ gap: 10 }} aria-label="Claim intent status">
              <p className="muted" style={{ fontSize: 12, margin: 0 }}>
                {t(
                  "待确认只表示认领意图已签名并保存，不表示来源 DAO 已确认占位。",
                  "Pending means the claim intent is signed and saved, not that the source DAO confirmed the claim.",
                )}
              </p>
              {claimIntentError && (
                <p role="alert" className="danger-text">
                  {t("认领状态暂不可用", "Claim status unavailable")}: {claimIntentError}
                </p>
              )}
              {!claimIntentError && claimIntents.length === 0 && (
                <div className="main-empty" style={{ minHeight: 180 }}>
                  <p>{t("暂无跨 DAO 认领记录。", "No cross-DAO claim records yet.")}</p>
                </div>
              )}
              {claimIntents.map((record) => {
                const { state, intent } = record;
                const isRecoverable = (
                  (state === "pending" || state === "expired")
                  && Boolean(record.source_peer && record.source_did && record.federation_key && record.receipt_id)
                );
                return (
                <article
                  key={intent.nonce}
                  className="task-claim-intent"
                  data-state={state}
                >
                  <div className="task-claim-intent-head">
                    <strong>{intent.announcement_id}</strong>
                    <span className={`pill claim-intent-${state}`}>{state}</span>
                  </div>
                  <div className="task-claim-intent-meta">
                    <span>{t("认领者", "Claimant")}: <code title={intent.claimant_did}>{intent.claimant_did.slice(0, 22)}…</code></span>
                    <span>{t("签署时间", "Signed")}: {new Date(intent.created_at_ms).toLocaleString()}</span>
                    <span>{t("有效期至", "Expires")}: {new Date(intent.expires_at_ms).toLocaleString()}</span>
                  </div>
                  {(state === "pending" || state === "expired") && (
                    <div className="task-claim-intent-actions">
                      {isRecoverable ? (
                        <button
                          className="btn btn-ghost"
                          type="button"
                          disabled={Boolean(reconcilingNonce)}
                          onClick={() => void handleReconcile(record)}
                        >
                          {reconcilingNonce === intent.nonce
                            ? t("恢复中…", "Reconciling…")
                            : t("向来源 DAO 核验", "Reconcile with source DAO")}
                        </button>
                      ) : (
                        <span className="muted" style={{ fontSize: 11 }}>
                          {t(
                            "旧版记录缺少来源绑定,无法自动恢复。",
                            "This legacy record lacks source bindings and cannot be reconciled automatically.",
                          )}
                        </span>
                      )}
                    </div>
                  )}
                </article>
                );
              })}
            </div>
          ) : shown.length === 0 ? (
            <div className="main-empty" style={{ minHeight: 200 }}>
              <div className="main-empty-icon">
                <IconBriefcase size={36} />
              </div>
              <p>
                {tab === "mine"
                  ? t("你还没发布任务。", "You haven't published any tasks.")
                  : t("市场上暂无可承接的活。", "No claimable work on the market.")}
              </p>
              <p className="muted" style={{ fontSize: 12, marginTop: 4 }}>
                {tab === "mine"
                  ? t("使用市场的统一发布入口创建任务。", "Use the unified Market publisher to create a Task.")
                  : t("换个筛选,或前往市场配置联邦节点。", "Adjust filters, or configure federation peers in Market.")}
              </p>
            </div>
          ) : (
            <div className="stack" style={{ gap: 10 }}>
              {shown.map((task) => (
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
                    <span className="pill dim" style={{ fontSize: 10 }}>
                      Task
                    </span>
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
                    {task.federation_stale && (
                      <span
                        className="pill dim"
                        title="The source did not complete its latest refresh. Refresh before claiming."
                        style={{ fontSize: 10, color: "var(--warning)" }}
                      >
                        stale
                      </span>
                    )}
                    {!task.federated && (
                      <span
                        className="pill dim"
                        style={{ fontSize: 10 }}
                        title={t("本节点发布", "Published by this DAO")}
                      >
                        {t("本节点", "local")}
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
                    {task.listing_type === "exchange" || task.claimable === false ? (
                      <span
                        className="pill"
                        style={{ marginLeft: "auto" }}
                        title="Publisher-signed discovery claim. Agreement is a separate protocol step."
                      >
                        Signed offer
                      </span>
                    ) : (
                      <button
                        className="btn"
                        disabled={
                          !claimAgent || task.federation_stale === true
                          || claimingId === task.announcement_id
                        }
                        title={
                          !claimAgent
                            ? t("先在左栏选一个认领 agent", "Pick a claiming agent in the left panel first")
                            : task.federated
                              ? t(
                                  "跨 DAO 认领:本地 agent 自签收据 → 回投到来源 DAO 落地",
                                  "Cross-DAO claim: your local agent signs, routed to the source DAO",
                                )
                              : t("用所选 agent 认领(agent 自签收据)", "Claim with selected agent (agent self-signs the receipt)")
                        }
                        style={{ marginLeft: "auto" }}
                        onClick={() => void handleClaim(task)}
                      >
                        {claimingId === task.announcement_id
                          ? t("认领中…", "Claiming…")
                          : task.federated
                            ? t("跨 DAO 认领", "claim (cross-DAO)")
                            : t("认领", "Claim")}
                      </button>
                    )}
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
