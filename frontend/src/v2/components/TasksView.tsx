/**
 * TasksView — 任务广场(发现态)。A2A 协调底座的核心面:发现可认领的活。
 *
 * 左栏:类别分面(context)+ 能力/赏金/搜索筛选。
 * 主区:公告卡片列表(标题/类别/能力/赏金/发布者)。
 * 认领按钮先占位禁用——认领是跨进程(切片B),由 agent 自己用私钥签。
 *
 * 自取数(import api),不经 App 状态,保持视图自洽。
 */
import { useEffect, useRef, useState } from "react";
import {
  claimFederatedTask, claimTask, fetchAgents, getClaimEvidence,
  getRecordedClaimCompletion,
  listClaimIntents, listOpenTasks,
  listTaskCategories, reconcileClaimIntent,
} from "../api";
import { IconBriefcase } from "./Icons";
import { ClaimSourceReceiptPanel } from "./ClaimSourceReceiptPanel";
import { SourceCompletionPanel } from "./SourceCompletionPanel";
import { useToast } from "./Toast";
import { relativeTimeShort } from "../utils/time";
import { useLang } from "../i18n";
import type {
  AgentEntry,
  ClaimEvidenceSummary,
  ClaimCompletionSummary,
  ClaimIntentPage,
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

function formatStorageBytes(bytes: number): string {
  if (bytes < 1024) return `${bytes} B`;
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KiB`;
  return `${(bytes / (1024 * 1024)).toFixed(1)} MiB`;
}

interface TasksViewProps {
  onOpenPublisher?: () => void;
}

const COMPLETION_CHECK_TIMEOUT_MS = 30_000;

export function TasksView({ onOpenPublisher }: TasksViewProps) {
  const toast = useToast();
  const { t } = useLang();
  const [tasks, setTasks] = useState<TaskAnnouncement[]>([]);
  const [cats, setCats] = useState<TaskCategory[]>([]);
  const [loading, setLoading] = useState(false);
  const [filtersOpen, setFiltersOpen] = useState(false);

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
  const [claimNextCursor, setClaimNextCursor] = useState<string | null>(null);
  const [claimLoadingMore, setClaimLoadingMore] = useState(false);
  const [claimPageError, setClaimPageError] = useState("");
  const claimMoreController = useRef<AbortController | null>(null);
  const [receiptStorage, setReceiptStorage] = useState<ClaimIntentPage["receipt_storage"]>();
  const [claimIntentError, setClaimIntentError] = useState("");
  const [claimIntentLoading, setClaimIntentLoading] = useState(true);
  const [claimIntentVersion, setClaimIntentVersion] = useState(0);
  const [reconcilingNonce, setReconcilingNonce] = useState("");
  const [retryEligibleNonce, setRetryEligibleNonce] = useState("");
  const [checkingEvidenceNonce, setCheckingEvidenceNonce] = useState("");
  const [claimEvidence, setClaimEvidence] = useState<Record<string, ClaimEvidenceSummary & { checkedAtMs: number }>>({});
  const [claimEvidenceError, setClaimEvidenceError] = useState<Record<string, string>>({});
  const evidenceController = useRef<AbortController | null>(null);
  const [checkingCompletionNonce, setCheckingCompletionNonce] = useState("");
  const [completionChecks, setCompletionChecks] = useState<Record<string, { summary: ClaimCompletionSummary | null; checkedAtMs: number }>>({});
  const [completionErrors, setCompletionErrors] = useState<Record<string, string>>({});
  const completionController = useRef<AbortController | null>(null);

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
    evidenceController.current?.abort();
    evidenceController.current = null;
    setCheckingEvidenceNonce("");
    setClaimEvidence({});
    setClaimEvidenceError({});
    completionController.current?.abort();
    completionController.current = null;
    setCheckingCompletionNonce("");
    setCompletionChecks({});
    setCompletionErrors({});
    claimMoreController.current?.abort();
    claimMoreController.current = null;
    setClaimIntentLoading(true);
    setClaimIntentError("");
    setRetryEligibleNonce("");
    setClaimPageError("");
    setClaimNextCursor(null);
    setClaimLoadingMore(false);
    listClaimIntents(100, ac.signal)
      .then((page) => {
        if (ac.signal.aborted) return;
        setClaimIntents(page.items);
        setClaimNextCursor(page.next_cursor ?? null);
        setReceiptStorage(page.receipt_storage);
        setClaimIntentLoading(false);
      })
      .catch((error) => {
        if (!ac.signal.aborted) {
          setReceiptStorage(undefined);
          setClaimIntentError(
            error instanceof Error || error instanceof DOMException
              ? error.message : String(error),
          );
          setClaimIntentLoading(false);
        }
      });
    return () => {
      ac.abort();
      evidenceController.current?.abort();
      completionController.current?.abort();
      claimMoreController.current?.abort();
    };
  }, [claimIntentVersion]);


  function selectTab(nextTab: "market" | "mine" | "claims") {
    if (tab === "claims" && nextTab !== "claims") {
      evidenceController.current?.abort();
      evidenceController.current = null;
      setCheckingEvidenceNonce("");
      setClaimEvidence({});
      setClaimEvidenceError({});
      completionController.current?.abort();
      completionController.current = null;
      setCheckingCompletionNonce("");
      setCompletionChecks({});
      setCompletionErrors({});
    }
    setTab(nextTab);
  }

  async function loadOlderClaims() {
    if (!claimNextCursor || claimLoadingMore || claimIntentLoading || claimIntentError) return;
    const cursor = claimNextCursor;
    const ac = new AbortController();
    claimMoreController.current = ac;
    setClaimLoadingMore(true);
    setClaimPageError("");
    try {
      const page = await listClaimIntents(100, ac.signal, cursor);
      if (ac.signal.aborted) return;
      setClaimIntents((current) => {
        const seen = new Set(current.map((record) => record.intent.nonce));
        return [...current, ...page.items.filter((record) => !seen.has(record.intent.nonce))];
      });
      setClaimNextCursor(page.next_cursor ?? null);
    } catch (error) {
      if (!ac.signal.aborted) {
        setClaimPageError(error instanceof Error ? error.message : String(error));
      }
    } finally {
      if (!ac.signal.aborted) setClaimLoadingMore(false);
      if (claimMoreController.current === ac) claimMoreController.current = null;
    }
  }

  const validReceiptStorage = receiptStorage
    && [receiptStorage.files, receiptStorage.used_bytes,
      receiptStorage.max_files, receiptStorage.max_bytes].every(Number.isFinite)
    && receiptStorage.files >= 0 && receiptStorage.used_bytes >= 0
    && receiptStorage.max_files > 0 && receiptStorage.max_bytes > 0
    ? receiptStorage : undefined;
  const receiptStorageFull = Boolean(validReceiptStorage && (
    validReceiptStorage.files >= validReceiptStorage.max_files
    || validReceiptStorage.used_bytes >= validReceiptStorage.max_bytes
  ));
  const receiptStorageNearLimit = !receiptStorageFull && Boolean(validReceiptStorage && (
    validReceiptStorage.files / validReceiptStorage.max_files >= 0.8
    || validReceiptStorage.used_bytes / validReceiptStorage.max_bytes >= 0.8
  ));

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

  async function handleClaim(task: TaskAnnouncement, agentDid = claimAgent) {
    if ((task.listing_type || "task") !== "task" || task.claimable === false) {
      toast.push(
        "This entry is not a claimable Task. Open it from Market instead.",
        "info",
      );
      return;
    }
    const annId = task.announcement_id;
    if (!agentDid || claimingId) return;
    setClaimingId(annId);
    const doClaim = () =>
      task.federated
        ? claimFederatedTask(annId, agentDid, task.federation_key || "")
        : claimTask(annId, agentDid);
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
        if (result.body.claimed === false) setRetryEligibleNonce(nonce);
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

  async function handleCheckEvidence(record: ClaimIntentRecord) {
    if (checkingEvidenceNonce || evidenceController.current) return;
    const nonce = record.intent.nonce;
    const ac = new AbortController();
    evidenceController.current = ac;
    setCheckingEvidenceNonce(nonce);
    setClaimEvidence((current) => {
      const next = { ...current };
      delete next[nonce];
      return next;
    });
    setClaimEvidenceError((current) => {
      const next = { ...current };
      delete next[nonce];
      return next;
    });
    try {
      const summary = await getClaimEvidence(nonce, ac.signal);
      if (!ac.signal.aborted) {
        if (
          summary.claim_receipt_id !== record.receipt_id
          || summary.claimant_did !== record.intent.claimant_did
          || !record.source_did
          || summary.source_did !== record.source_did
        ) {
          throw new Error("Claim evidence does not match this claim");
        }
        setClaimEvidence((current) => ({
          ...current, [nonce]: { ...summary, checkedAtMs: Date.now() },
        }));
      }
    } catch (error) {
      if (!ac.signal.aborted) {
        setClaimEvidenceError((current) => ({
          ...current,
          [nonce]: error instanceof Error ? error.message : String(error),
        }));
      }
    } finally {
      if (evidenceController.current === ac) {
        evidenceController.current = null;
        if (!ac.signal.aborted) setCheckingEvidenceNonce("");
      }
    }
  }

  async function handleCheckCompletion(record: ClaimIntentRecord) {
    if (checkingCompletionNonce || completionController.current) return;
    const nonce = record.intent.nonce;
    const ac = new AbortController();
    completionController.current = ac;
    setCheckingCompletionNonce(nonce);
    setCompletionChecks((current) => {
      const next = { ...current };
      delete next[nonce];
      return next;
    });
    setCompletionErrors((current) => {
      const next = { ...current };
      delete next[nonce];
      return next;
    });
    let timer: ReturnType<typeof setTimeout> | undefined;
    let onAbort: (() => void) | undefined;
    let timedOut = false;
    try {
      const deadline = new Promise<never>((_, reject) => {
        timer = setTimeout(() => {
          timedOut = true;
          ac.abort();
          reject(new Error("Signed completion check timed out; retry."));
        }, COMPLETION_CHECK_TIMEOUT_MS);
      });
      const cancelled = new Promise<never>((_, reject) => {
        onAbort = () => reject(new DOMException("Aborted", "AbortError"));
        ac.signal.addEventListener("abort", onAbort, { once: true });
      });
      const summary = await Promise.race([
        getRecordedClaimCompletion(nonce, ac.signal), deadline, cancelled,
      ]);
      if (!ac.signal.aborted) {
        setCompletionChecks((current) => ({
          ...current, [nonce]: { summary, checkedAtMs: Date.now() },
        }));
      }
    } catch (error) {
      if (completionController.current === ac && (!ac.signal.aborted || timedOut)) {
        setCompletionErrors((current) => ({
          ...current,
          [nonce]: timedOut
            ? "Signed completion check timed out; retry."
            : error instanceof Error ? error.message : String(error),
        }));
      }
    } finally {
      clearTimeout(timer);
      if (onAbort) ac.signal.removeEventListener("abort", onAbort);
      if (completionController.current === ac) {
        completionController.current = null;
        if (!ac.signal.aborted || timedOut) setCheckingCompletionNonce("");
      }
    }
  }

  return (
    <>
      <aside className={`sidebar tasks-sidebar${filtersOpen ? " tasks-filters-open" : ""}`} id="tasks-filters">
        <div className="sidebar-head">
          <span className="sidebar-title">{t("类别", "Categories")}</span>
          <span className="sidebar-count">{cats.length}</span>
          <button className="tasks-filter-toggle btn btn-ghost" type="button" onClick={() => setFiltersOpen(false)}>Close filters</button>
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

      <section className="main tasks-main" style={{ display: "flex", flexDirection: "column" }}>
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
            <h1 className="main-title">Tasks {loading ? "…" : `(${tab === "claims" ? (claimIntentError || claimIntentLoading ? "?" : `${claimIntents.length}${claimNextCursor ? "+" : ""}`) : shown.length})`}</h1>
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
          <button className="tasks-filter-toggle btn btn-ghost" type="button"
            aria-controls="tasks-filters" aria-expanded={filtersOpen}
            onClick={() => setFiltersOpen((current) => !current)}>Filters</button>
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
              onClick={() => selectTab("market")}
              title={t("各 DAO 发布的、可承接的活(含联邦)", "Claimable work from across DAOs (incl. federated)")}
            >
              Available ({tasks.length})
            </button>
            <button
              className={`btn ${tab === "mine" ? "btn-primary" : "btn-ghost"}`}
              style={{ fontSize: 12 }}
              onClick={() => selectTab("mine")}
              title={t("本节点发布、供他人认领的活", "Tasks this DAO published for others to claim")}
            >
              {t("我发布的", "My published")} ({myTasks.length})
            </button>
            <button
              className={`btn ${tab === "claims" ? "btn-primary" : "btn-ghost"}`}
              style={{ fontSize: 12 }}
              onClick={() => selectTab("claims")}
            >
              {t("我的认领", "My claims")} ({claimIntentError || claimIntentLoading ? "?" : `${claimIntents.length}${claimNextCursor ? "+" : ""}`})
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

          {tab === "mine" && <SourceCompletionPanel />}
          {tab === "claims" ? (
            <div className="stack" style={{ gap: 10 }} aria-label="Claim intent status">
              <div style={{ display: "flex", alignItems: "center", gap: 12, flexWrap: "wrap" }}>
                <p className="muted" style={{ fontSize: 12, margin: 0, flex: 1 }}>
                  {t(
                    "待确认只表示认领意图已签名并保存，不表示来源 DAO 已确认占位。",
                    "Pending means the claim intent is signed and saved, not that the source DAO confirmed the claim.",
                  )}
                </p>
                <button className="btn btn-ghost" type="button"
                  onClick={() => setClaimIntentVersion((version) => version + 1)}>
                  {t("刷新", "Refresh")}
                </button>
              </div>
              {claimIntentLoading && (
                <p role="status" className="muted" style={{ fontSize: 12, margin: 0 }}>
                  {t("认领状态刷新中…", "Refreshing claim status…")}
                </p>
              )}
              {!claimIntentLoading && claimIntentError && (
                <p role="alert" className="danger-text">
                  {t("认领状态暂不可用", "Claim status unavailable")}: {claimIntentError}
                </p>
              )}
              {!claimIntentLoading && !claimIntentError && validReceiptStorage && (
                <p role="status" className={receiptStorageNearLimit || receiptStorageFull ? "danger-text" : "muted"}
                  style={{ fontSize: 12, margin: 0 }}>
                  {t("认领回执磁盘占用（非完整性校验）", "Claim receipt disk usage (not an integrity check)")}: {formatStorageBytes(validReceiptStorage.used_bytes)}
                  {" / "}{formatStorageBytes(validReceiptStorage.max_bytes)}
                  {" · "}{validReceiptStorage.files} / {validReceiptStorage.max_files} {t("文件", "files")}
                  {receiptStorageFull && (
                    <> · {t("容量已满，新认领将失败。", "Capacity full; new claims will fail.")}</>
                  )}
                  {receiptStorageNearLimit && (
                    <> · {t("接近容量上限，新认领可能失败。", "Near capacity; new claims may fail.")}</>
                  )}
                </p>
              )}
              {!claimIntentLoading && !claimIntentError && claimIntents.length === 0 && (
                <div className="main-empty" style={{ minHeight: 180 }}>
                  <p>{t("暂无跨 DAO 认领记录。", "No cross-DAO claim records yet.")}</p>
                </div>
              )}
              {!claimIntentLoading && !claimIntentError && claimIntents.map((record) => {
                const { state, intent } = record;
                const freshListing = tasks.find((task) => (
                  task.federated === true
                  && task.claimable !== false
                  && task.federation_stale !== true
                  && task.announcement_id === intent.announcement_id
                  && task.federation_key === record.federation_key
                  && task.source_peer === record.source_peer
                ));
                const sameAgentOnline = agents.some((agent) => agent.did === intent.claimant_did);
                const isRecoverable = (
                  (state === "pending" || state === "expired")
                  && Boolean(record.source_peer && record.source_did && record.federation_key && record.receipt_id)
                );
                const completionCheck = completionChecks[intent.nonce];
                const completionSummary = completionCheck?.summary;
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
                      {retryEligibleNonce === intent.nonce && (
                        freshListing && sameAgentOnline ? (
                          <button className="btn btn-ghost" type="button"
                            disabled={Boolean(claimingId || reconcilingNonce)}
                            onClick={() => void handleClaim(freshListing, intent.claimant_did)}>
                            {t("重新签名认领", "Sign a fresh claim")}
                          </button>
                        ) : (
                          <span className="muted" style={{ fontSize: 11 }}>
                            {t(
                              "要重新认领，请先刷新来源公告并确保原 Agent 在线。旧记录仍待确认。",
                              "For a fresh claim, refresh the source listing and bring the original Agent online. The old record remains unconfirmed.",
                            )}
                          </span>
                        )
                      )}
                    </div>
                  )}
                  {state === "confirmed" && <>
                    <div className="task-claim-intent-actions">
                      <button className="btn btn-ghost" type="button"
                        disabled={Boolean(checkingEvidenceNonce)}
                        onClick={() => void handleCheckEvidence(record)}>
                        {checkingEvidenceNonce === intent.nonce
                          ? "Checking…"
                          : "Verify claim evidence"}
                      </button>
                      <button className="btn btn-ghost" type="button"
                        disabled={Boolean(checkingCompletionNonce)}
                        onClick={() => void handleCheckCompletion(record)}>
                        {checkingCompletionNonce === intent.nonce
                          ? "Checking…"
                          : "Check signed completion"}
                      </button>
                    </div>
                    {claimEvidenceError[intent.nonce] && <p role="alert" className="danger-text">
                      Claim evidence unavailable: {claimEvidenceError[intent.nonce]}
                    </p>}
                    {claimEvidence[intent.nonce] && <div className="task-claim-evidence" role="status">
                      <strong>Claim evidence verified</strong>
                      <span>Scope: Signed claim only</span>
                      <span>Checked locally: <time dateTime={new Date(claimEvidence[intent.nonce].checkedAtMs).toISOString()}>{new Date(claimEvidence[intent.nonce].checkedAtMs).toLocaleString()}</time></span>
                      <span>Claim receipt: <code title={claimEvidence[intent.nonce].claim_receipt_id}>{claimEvidence[intent.nonce].claim_receipt_id.slice(0, 18)}…</code></span>
                      <span>Authority ACK: <code title={claimEvidence[intent.nonce].authority_ack_id}>{claimEvidence[intent.nonce].authority_ack_id.slice(0, 18)}…</code></span>
                      <span>Source DID: <code title={claimEvidence[intent.nonce].source_did}>{claimEvidence[intent.nonce].source_did.slice(0, 22)}…</code></span>
                      {claimEvidence[intent.nonce].mission_id && <span>
                        Advertised mission ID: <code>{claimEvidence[intent.nonce].mission_id}</code>
                      </span>}
                    </div>}
                    {completionErrors[intent.nonce] && <p role="alert" className="danger-text">
                      Completion evidence unavailable: {completionErrors[intent.nonce]}
                    </p>}
                    {completionCheck && <div className="task-claim-evidence" role="status">
                      {completionSummary ? <>
                        <strong>Signed completion statement recorded</strong>
                        <span>Claimant-reported outcome: {completionSummary.outcome}</span>
                        {(completionSummary.revision ?? 0) > 0 && <span>Revision {completionSummary.revision} (prior statement retained)</span>}
                        <span>Signed evidence only. Not work acceptance or payment.</span>
                        <span>Source claim ID: <code title={completionSummary.source_claim_id}>{completionSummary.source_claim_id.slice(0, 18)}…</code></span>
                        <span>Local nonce is not source-authenticated.</span>
                        <span>Mission ID: <code>{completionSummary.mission_id}</code></span>
                        <span>Evidence: <code title={completionSummary.evidence_digest}>{completionSummary.evidence_digest.slice(0, 25)}…</code></span>
                      </> : <span>No signed completion statement recorded</span>}
                    </div>}
                    {completionSummary?.completion_head_digest && <ClaimSourceReceiptPanel
                      key={`${intent.nonce}:${completionSummary.completion_head_digest}`}
                      nonce={intent.nonce}
                      head={completionSummary.completion_head_digest}
                      sourceClaimId={completionSummary.source_claim_id}
                      sourceDid={record.source_did || ""}
                      claimantDid={intent.claimant_did}
                    />}
                  </>}
                </article>
                );
              })}
              {!claimIntentLoading && !claimIntentError && claimNextCursor && (
                <button className="btn btn-ghost" type="button"
                  disabled={claimLoadingMore} onClick={() => void loadOlderClaims()}>
                  {claimLoadingMore ? t("加载中…", "Loading…") : t("加载更早认领", "Load older claims")}
                </button>
              )}
              {!claimIntentLoading && !claimIntentError && claimPageError && (
                <p role="alert" className="danger-text">
                  {t("更早认领加载失败", "Older claims unavailable")}: {claimPageError}
                </p>
              )}
            </div>
          ) : shown.length === 0 ? (
            <div className="main-empty" style={{ minHeight: 200 }}>
              <div className="main-empty-icon">
                <IconBriefcase size={36} />
              </div>
              <p>
                {tab === "mine"
                  ? "No unclaimed local tasks match these filters."
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
