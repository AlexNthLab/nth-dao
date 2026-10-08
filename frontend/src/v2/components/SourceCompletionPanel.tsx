import { useEffect, useRef, useState } from "react";
import {
  ApiHttpError, SourceCompletionLookupState, PORTABLE_COMPLETION_PROOF_INPUT_LIMIT_BYTES,
  getRecordedSourceCompletion, recordSourceCompletionProof, verifySourceCompletionProof,
} from "../api";
import type { SourceCompletionCheck } from "../types-v2";

type Download = Awaited<ReturnType<typeof getRecordedSourceCompletion>>;
const REQUEST_TIMEOUT_MS = 30_000;

export function SourceCompletionPanel() {
  const [file, setFile] = useState<{ name: string; raw: string } | null>(null);
  const [check, setCheck] = useState<SourceCompletionCheck | null>(null);
  const [receipt, setReceipt] = useState<Download | null>(null);
  const [busy, setBusy] = useState("");
  const [eligible, setEligible] = useState(false);
  const [unknown, setUnknown] = useState(false);
  const [error, setError] = useState("");
  const [notice, setNotice] = useState("");
  const active = useRef(true);
  const locked = useRef(false);
  const fileVersion = useRef(0);
  const controller = useRef<AbortController | null>(null);
  const downloadUrl = useRef<string | null>(null);
  const downloadTimer = useRef<ReturnType<typeof setTimeout> | undefined>(undefined);

  useEffect(() => {
    active.current = true;
    return () => {
      active.current = false;
      fileVersion.current += 1;
      controller.current?.abort();
    };
  }, []);

  async function request<T>(call: (signal: AbortSignal) => Promise<T>): Promise<T> {
    const ac = new AbortController();
    controller.current = ac;
    let timer: ReturnType<typeof setTimeout> | undefined;
    const timeout = new Promise<never>((_, reject) => {
      timer = setTimeout(() => {
        ac.abort();
        reject(new Error("Source receipt request timed out"));
      }, REQUEST_TIMEOUT_MS);
    });
    try { return await Promise.race([call(ac.signal), timeout]); }
    finally {
      clearTimeout(timer);
      if (controller.current === ac) controller.current = null;
    }
  }

  function finish() {
    locked.current = false;
    if (active.current) setBusy("");
  }

  async function selectFile(selected: File | undefined) {
    if (locked.current || unknown) return;
    const version = ++fileVersion.current;
    setFile(null); setCheck(null); setReceipt(null); setEligible(false);
    setError(""); setNotice("");
    if (!selected) return;
    if (selected.size > PORTABLE_COMPLETION_PROOF_INPUT_LIMIT_BYTES) {
      setError("Completion proof exceeds the 20 MiB size limit");
      return;
    }
    try {
      const raw = await selected.text();
      if (active.current && fileVersion.current === version) {
        setFile({ name: selected.name, raw });
      }
    } catch {
      if (active.current && fileVersion.current === version) setError("Could not read completion proof file");
    }
  }

  async function readStored(selected: SourceCompletionCheck): Promise<Download> {
    if (!selected.source_claim_id || !selected.completion_head_digest || !selected.proof_digest) {
      throw new Error("Verified completion selectors are unavailable");
    }
    const downloaded = await request((signal) => getRecordedSourceCompletion(
      selected.source_claim_id!, selected.completion_head_digest!, signal,
    ));
    if (downloaded.summary.proof_digest !== selected.proof_digest) {
      throw new Error("Retained source receipt binds a different proof");
    }
    return downloaded;
  }

  async function inspect(selected: SourceCompletionCheck, afterWrite = false) {
    try {
      const downloaded = await readStored(selected);
      if (active.current) {
        setReceipt(downloaded); setEligible(false); setUnknown(false);
        setNotice("Source receipt recorded and reverified.");
      }
    } catch (cause) {
      if (!active.current) return;
      setReceipt(null);
      if (cause instanceof SourceCompletionLookupState) {
        setEligible(true); setUnknown(false);
        setNotice(cause.state === "pending_audit"
          ? "Proof retained; source audit is pending. Record again to finish it."
          : "No source receipt recorded for this proof.");
      } else {
        setEligible(false); setUnknown(afterWrite);
        throw cause;
      }
    }
  }

  async function verify() {
    if (locked.current || !file || unknown) return;
    locked.current = true; setBusy("verify");
    setError(""); setNotice(""); setCheck(null); setReceipt(null); setEligible(false);
    try {
      const result = await request((signal) => verifySourceCompletionProof(file.raw, signal));
      if (!active.current) return;
      setCheck(result);
      if (!result.verified) { setError(result.reason); return; }
      await inspect(result);
    } catch (cause) {
      if (active.current) setError(cause instanceof Error ? cause.message : "Proof verification failed");
    } finally { finish(); }
  }

  async function record() {
    if (locked.current || !file || !check?.verified || !eligible || unknown) return;
    locked.current = true; setBusy("record");
    setError(""); setNotice(""); setEligible(false); setUnknown(true);
    try {
      await request((signal) => recordSourceCompletionProof(
        file.raw, check.source_claim_id!, check.completion_head_digest!, check.proof_digest!, signal,
      ));
      if (active.current) await inspect(check, true);
    } catch (cause) {
      if (!active.current) return;
      if (cause instanceof ApiHttpError && [400, 401, 403, 409, 413, 415, 422].includes(cause.status)) {
        setUnknown(false); setCheck(null);
        setError(`Record rejected (HTTP ${cause.status}); verify the proof again.`);
      } else {
        try {
          await inspect(check, true);
          if (active.current) setError("Record request did not finish normally; receipt status was rechecked.");
        } catch {
          if (active.current) setError("Record outcome unknown. Check source receipt before retrying.");
        }
      }
    } finally { finish(); }
  }

  async function checkReceipt() {
    if (locked.current || !check?.verified) return;
    locked.current = true; setBusy("check"); setError(""); setNotice("");
    try { await inspect(check, unknown); }
    catch (cause) {
      if (active.current) setError(cause instanceof Error ? cause.message : "Receipt check failed");
    } finally { finish(); }
  }

  async function download() {
    if (locked.current || !check?.verified || !receipt) return;
    locked.current = true; setBusy("download"); setError("");
    try {
      const current = await readStored(check);
      if (!active.current) return;
      setReceipt(current);
      if (downloadUrl.current) URL.revokeObjectURL(downloadUrl.current);
      clearTimeout(downloadTimer.current);
      const urlApi = URL;
      const url = urlApi.createObjectURL(new Blob([current.raw], { type: "application/json;charset=utf-8" }));
      downloadUrl.current = url;
      downloadTimer.current = setTimeout(() => {
        urlApi.revokeObjectURL(url);
        if (downloadUrl.current === url) downloadUrl.current = null;
      }, 60_000);
      const link = document.createElement("a");
      link.href = url;
      link.download = `nth-source-receipt-${check.source_claim_id!.slice(0, 12)}-${check.completion_head_digest!.slice(7, 19)}.json`;
      document.body.append(link);
      try { link.click(); } finally { link.remove(); }
      setNotice("Receipt download requested. Share it with the claimant DAO.");
    } catch (cause) {
      if (active.current) {
        setReceipt(null); setEligible(false);
        setError(cause instanceof Error ? cause.message : "Receipt download failed");
      }
    } finally { finish(); }
  }

  return <section className="source-completion-workbench" aria-label="Source completion receipts">
    <h2>Completion receipts</h2>
    <label className="source-completion-file">
      Claimant proof file
      <input type="file" accept=".json,application/json" disabled={Boolean(busy) || unknown}
        onChange={(event) => { const selected = event.target.files?.[0]; event.target.value = ""; void selectFile(selected); }} />
    </label>
    {file && <p className="muted source-completion-value">{file.name}</p>}
    <div className="source-completion-actions">
      <button type="button" className="btn btn-ghost" disabled={!file || Boolean(busy) || unknown} onClick={() => void verify()}>
        {busy === "verify" ? "Verifying..." : "Verify proof"}
      </button>
      <button type="button" className="btn btn-primary" disabled={!eligible || !check?.verified || Boolean(busy) || unknown}
        onClick={() => void record()}>{busy === "record" ? "Recording..." : "Record and sign receipt"}</button>
      <button type="button" className="btn btn-ghost" disabled={!check?.verified || Boolean(busy)} onClick={() => void checkReceipt()}>
        {busy === "check" ? "Checking..." : "Check source receipt"}
      </button>
      <button type="button" className="btn btn-ghost" disabled={!receipt || Boolean(busy)} onClick={() => void download()}>
        {busy === "download" ? "Preparing..." : "Download source receipt"}
      </button>
    </div>
    {check?.verified && <dl className="source-completion-summary">
      <dt>Mission</dt><dd>{check.mission_id}</dd>
      <dt>Claimant-reported result</dt><dd>{check.outcome}</dd>
      <dt>Source claim</dt><dd>{check.source_claim_id}</dd>
      <dt>Completion head</dt><dd>{check.completion_head_digest}</dd>
      {receipt && <><dt>Receipt signer</dt><dd>{receipt.summary.source_receipt_event.author_did}</dd></>}
    </dl>}
    {receipt && receipt.summary.lineage_state !== "single_retained_head" && <p className="danger-text">
      {receipt.summary.lineage_state.startsWith("pending_")
        ? "Other source evidence is pending audit or repair. No unique result is established."
        : "Multiple statements retained. This receipt covers the selected completion only."}
    </p>}
    {check?.verified && <p className="muted">Claimant statement verified. Work acceptance and payment remain separate.</p>}
    {notice && <p role="status" className="muted">{notice}</p>}
    {error && <p role="alert" className="danger-text">{error}</p>}
  </section>;
}
