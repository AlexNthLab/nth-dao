import { useEffect, useRef, useState } from "react";

import {
  ApiHttpError,
  SOURCE_RECEIPT_INPUT_LIMIT_BYTES,
  getPortableClaimCompletionProof,
  getClaimSourceReceiptStatus,
  importClaimSourceReceipt,
  reconcileClaimSourceReceipt,
} from "../api";
import type { ClaimSourceReceiptStatus } from "../types-v2";

const RECEIPT_REQUEST_TIMEOUT_MS = 30_000;
const PROOF_DOWNLOAD_URL_LIFETIME_MS = 60_000;

interface ClaimSourceReceiptPanelProps {
  nonce: string;
  head: string;
  sourceClaimId: string;
  sourceDid: string;
  claimantDid: string;
}

function selectedReceipt(raw: string, head: string, sourceClaimId: string): string {
  if (new TextEncoder().encode(raw).byteLength > SOURCE_RECEIPT_INPUT_LIMIT_BYTES) {
    throw new Error("Source receipt exceeds the import size limit");
  }
  let value: unknown;
  try {
    value = JSON.parse(raw);
  } catch {
    throw new Error("Invalid source receipt JSON");
  }
  if (!value || typeof value !== "object" || Array.isArray(value)) {
    throw new Error("Invalid source receipt JSON");
  }
  const response = value as Record<string, unknown>;
  const event = "source_receipt_event" in response ? response.source_receipt_event : response;
  if (!event || typeof event !== "object" || Array.isArray(event)) {
    throw new Error("Invalid source receipt JSON");
  }
  const payload = (event as Record<string, unknown>).payload;
  if (!payload || typeof payload !== "object" || Array.isArray(payload)) {
    throw new Error("Invalid source receipt JSON");
  }
  const fields = payload as Record<string, unknown>;
  if (fields.completion_head_digest !== head || fields.source_claim_id !== sourceClaimId) {
    throw new Error("Source receipt does not match this completion");
  }
  return raw;
}

export function ClaimSourceReceiptPanel({
  nonce, head, sourceClaimId, sourceDid, claimantDid,
}: ClaimSourceReceiptPanelProps) {
  const [status, setStatus] = useState<ClaimSourceReceiptStatus | null>(null);
  const [checked, setChecked] = useState(false);
  const [open, setOpen] = useState(false);
  const [raw, setRaw] = useState("");
  const [busy, setBusy] = useState<"" | "check" | "export" | "import" | "reconcile">("");
  const [error, setError] = useState("");
  const [notice, setNotice] = useState("");
  const [unattributedImport, setUnattributedImport] = useState(false);
  const busyRef = useRef(false);
  const requestController = useRef<AbortController | null>(null);
  const proofDownload = useRef<{ raw: string; url: string } | null>(null);
  const active = useRef(true);
  const fileReadVersion = useRef(0);

  useEffect(() => {
    active.current = true;
    return () => {
      active.current = false;
      fileReadVersion.current += 1;
      requestController.current?.abort();
    };
  }, []);

  function inspect(value: ClaimSourceReceiptStatus | null): ClaimSourceReceiptStatus | null {
    if (value && value.source_claim_id !== sourceClaimId) {
      throw new Error("Source receipt belongs to another claim");
    }
    return value;
  }

  async function withDeadline<T>(
    request: (signal: AbortSignal) => Promise<T>, timeoutMessage: string,
  ): Promise<T> {
    const controller = new AbortController();
    requestController.current = controller;
    let timer: ReturnType<typeof setTimeout> | undefined;
    let timedOut = false;
    const deadline = new Promise<never>((_, reject) => {
      timer = setTimeout(() => {
        timedOut = true;
        controller.abort();
        reject(new Error(timeoutMessage));
      }, RECEIPT_REQUEST_TIMEOUT_MS);
    });
    try {
      return await Promise.race([request(controller.signal), deadline]);
    } catch (cause) {
      if (timedOut) throw new Error(timeoutMessage);
      throw cause;
    } finally {
      clearTimeout(timer);
      if (requestController.current === controller) requestController.current = null;
    }
  }

  function isDefiniteRejection(cause: unknown): boolean {
    return cause instanceof ApiHttpError
      && [400, 401, 403, 404, 405, 409, 410, 413, 415, 422].includes(cause.status);
  }

  async function recoverWrite(kind: "Import" | "Reconciliation", expectedDigest?: string) {
    if (!active.current) return;
    try {
      const current = inspect(await withDeadline(
        (signal) => getClaimSourceReceiptStatus(nonce, head, signal),
        "Source receipt check timed out",
      ));
      if (!active.current) return;
      if (!current || (expectedDigest && current.expected_response_digest !== expectedDigest)) {
        setStatus(null);
        setChecked(false);
        setUnattributedImport(false);
        setNotice("");
        setError(`${kind} outcome unknown. Check source receipt before retrying.`);
        return;
      }
      setStatus(current);
      setChecked(true);
      setUnattributedImport(kind === "Import");
      setError("");
      setNotice(current.pending
        ? kind === "Import"
          ? "A verified source receipt is retained, but may predate this import. Check it separately before reconciliation; this submission outcome is uncertain."
          : "A verified source receipt is retained; local audit is pending."
        : kind === "Import"
          ? "A source receipt is observed locally, but may predate this import; this submission outcome is uncertain."
          : "The exact retained source receipt is observed locally.");
    } catch {
      if (!active.current) return;
      setStatus(null);
      setChecked(false);
      setUnattributedImport(false);
      setNotice("");
      setError(`${kind} outcome unknown; local status could not be checked. Try Check source receipt before retrying.`);
    }
  }

  async function check() {
    if (busyRef.current) return;
    busyRef.current = true;
    setBusy("check");
    setError("");
    setNotice("");
    try {
      const result = inspect(await withDeadline(
        (signal) => getClaimSourceReceiptStatus(nonce, head, signal),
        "Source receipt check timed out",
      ));
      if (active.current) {
        setStatus(result);
        setChecked(true);
        setUnattributedImport(false);
      }
    } catch (cause) {
      if (active.current) {
        setStatus(null);
        setChecked(false);
        setError(cause instanceof Error ? cause.message : "Source receipt check failed");
      }
    } finally {
      busyRef.current = false;
      if (active.current) setBusy("");
    }
  }

  async function exportProof() {
    if (busyRef.current) return;
    busyRef.current = true;
    setBusy("export");
    setError("");
    setNotice("");
    try {
      const rawProof = await withDeadline(
        (signal) => getPortableClaimCompletionProof(nonce, head, sourceClaimId, signal),
        "Completion proof export timed out",
      );
      if (!active.current) return;
      const urlApi = URL;
      const retained = proofDownload.current;
      if (retained && retained.raw !== rawProof) {
        throw new Error("Completion proof changed for the same head; reload before exporting");
      }
      const url = retained?.url ?? urlApi.createObjectURL(new Blob(
        [rawProof], { type: "application/json;charset=utf-8" },
      ));
      if (!retained) {
        proofDownload.current = { raw: rawProof, url };
        setTimeout(() => {
          urlApi.revokeObjectURL(url);
          if (proofDownload.current?.url === url) proofDownload.current = null;
        }, PROOF_DOWNLOAD_URL_LIFETIME_MS);
      }
      const link = document.createElement("a");
      link.href = url;
      link.download = `nth-completion-${sourceClaimId.slice(0, 12)}-${head.slice(7, 19)}.json`;
      document.body.append(link);
      try {
        link.click();
      } finally {
        link.remove();
      }
      setNotice("Download requested; check your browser's downloads before sharing with the intended source DAO.");
    } catch (cause) {
      if (active.current) {
        setError(cause instanceof Error ? cause.message : "Completion proof export failed");
      }
    } finally {
      busyRef.current = false;
      if (active.current) setBusy("");
    }
  }

  async function importReceipt() {
    if (busyRef.current) return;
    busyRef.current = true;
    setBusy("import");
    setError("");
    setNotice("");
    let sent = false;
    let responseInconsistent = false;
    try {
      const response = selectedReceipt(raw, head, sourceClaimId);
      sent = true;
      const result = await withDeadline(
        (signal) => importClaimSourceReceipt(nonce, head, sourceClaimId, response, signal),
        "Source receipt import timed out; outcome unknown. Check source receipt before retrying.",
      );
      if ((sourceDid && result.source_did !== sourceDid)
        || result.claimant_did !== claimantDid) {
        responseInconsistent = true;
        throw new Error("Source receipt identity differs from this claim");
      }
      const current = inspect(await withDeadline(
        (signal) => getClaimSourceReceiptStatus(nonce, head, signal),
        "Source receipt check timed out",
      ));
      if (!current?.observed_locally) throw new Error("Source receipt is not locally observed");
      if (active.current) {
        setStatus(current);
        setChecked(true);
        setUnattributedImport(false);
        setRaw("");
        setOpen(false);
      }
    } catch (cause) {
      if (responseInconsistent || isDefiniteRejection(cause) || !sent) {
        if (active.current) {
          if (sent) { setStatus(null); setChecked(false); }
          setUnattributedImport(false);
          setError(cause instanceof ApiHttpError && cause.status === 409
            ? "Source receipt conflicts with retained local evidence (HTTP 409). Check the current receipt before retrying."
            : cause instanceof Error ? cause.message : "Source receipt import failed");
        }
      } else {
        await recoverWrite("Import");
      }
    } finally {
      busyRef.current = false;
      if (active.current) setBusy("");
    }
  }

  async function reconcile() {
    if (busyRef.current || unattributedImport || !status?.pending) return;
    const expectedDigest = status.expected_response_digest;
    busyRef.current = true;
    setBusy("reconcile");
    setError("");
    setNotice("");
    let responseInconsistent = false;
    try {
      const result = await withDeadline(
        (signal) => reconcileClaimSourceReceipt(
          nonce, head, sourceClaimId, expectedDigest, signal,
        ),
        "Source receipt reconciliation timed out; outcome unknown. Check source receipt before retrying.",
      );
      if ((sourceDid && result.source_did !== sourceDid)
        || result.claimant_did !== claimantDid) {
        responseInconsistent = true;
        throw new Error("Source receipt identity differs from this claim");
      }
      const current = inspect(await withDeadline(
        (signal) => getClaimSourceReceiptStatus(nonce, head, signal),
        "Source receipt check timed out",
      ));
      if (!current?.observed_locally) throw new Error("Source receipt is not locally observed");
      if (active.current) {
        setStatus(current);
        setChecked(true);
      }
    } catch (cause) {
      if (responseInconsistent || isDefiniteRejection(cause)) {
        if (active.current) {
          setStatus(null);
          setChecked(false);
          setError(cause instanceof Error ? cause.message : "Source receipt reconciliation failed");
        }
      } else {
        await recoverWrite("Reconciliation", expectedDigest);
      }
    } finally {
      busyRef.current = false;
      if (active.current) setBusy("");
    }
  }

  async function loadFile(file: File | undefined) {
    if (!file) return;
    const version = ++fileReadVersion.current;
    setRaw("");
    setError("");
    if (file.size > SOURCE_RECEIPT_INPUT_LIMIT_BYTES) {
      setError("Source receipt exceeds the import size limit");
      return;
    }
    try {
      const content = await file.text();
      if (active.current && fileReadVersion.current === version) {
        if (new TextEncoder().encode(content).byteLength > SOURCE_RECEIPT_INPUT_LIMIT_BYTES) {
          setError("Source receipt exceeds the import size limit");
          return;
        }
        setRaw(content);
      }
    } catch {
      if (active.current && fileReadVersion.current === version) {
        setError("Could not read source receipt file");
      }
    }
  }

  return <section className="task-source-receipt" aria-label="Source receipt">
    <div className="task-claim-intent-actions">
      <button className="btn btn-ghost" type="button" disabled={Boolean(busy)} onClick={() => void check()}>
        {busy === "check" ? "Checking…" : "Check source receipt"}
      </button>
      <button className="btn btn-ghost" type="button" disabled={Boolean(busy)}
        onClick={() => void exportProof()} title="Save the exact signed completion ancestry for manual transfer">
        {busy === "export" ? "Preparing…" : "Download proof"}
      </button>
      <button className="btn btn-ghost" type="button" disabled={Boolean(busy)}
        onClick={() => { fileReadVersion.current += 1; setOpen(!open); setRaw(""); setError(""); }}>
        {open ? "Close import" : "Import source receipt"}
      </button>
    </div>
    <p className="muted task-source-receipt-note">
      Proof contains a scoped capability token and participant metadata. Share only with the intended source DAO. Not acceptance or payment.
    </p>
    {checked && !status && <span className="muted">No source receipt retained for this completion</span>}
    {status?.pending && <div className="task-claim-evidence" role="status">
      <strong>Verified file awaits local audit</strong>
      <span>Source statement only. Not work acceptance or payment.</span>
      <span>Receipt digest to audit: <code>{status.expected_response_digest}</code></span>
      <button className="btn btn-ghost" type="button" disabled={Boolean(busy || unattributedImport)}
        onClick={() => void reconcile()}>
        {busy === "reconcile" ? "Reconciling…" : "Reconcile retained receipt"}
      </button>
    </div>}
    {status?.observed_locally && <div className="task-claim-evidence" role="status">
      <strong>Source statement observed locally</strong>
      <span>Not work acceptance or payment.</span>
      <span>Local observation: <code title={status.local_observation_event_id || ""}>
        {status.local_observation_event_id?.slice(0, 18)}…
      </code></span>
    </div>}
    {error && <p role="alert" className="danger-text">{error}</p>}
    {notice && <p role="status" className="muted">{notice}</p>}
    {open && <div className="task-source-receipt-form">
      <label htmlFor={`source-receipt-${nonce}`}>Signed source receipt JSON</label>
      <textarea id={`source-receipt-${nonce}`} value={raw}
        onChange={(event) => { fileReadVersion.current += 1; setRaw(event.target.value); }}
        disabled={Boolean(busy)} maxLength={SOURCE_RECEIPT_INPUT_LIMIT_BYTES}
        spellCheck={false} />
      <input type="file" accept=".json,application/json" aria-label="Choose source receipt JSON"
        disabled={Boolean(busy)} onChange={(event) => void loadFile(event.target.files?.[0])} />
      <button className="btn btn-ghost" type="button" disabled={Boolean(busy || !raw.trim())}
        onClick={() => void importReceipt()}>
        {busy === "import" ? "Verifying…" : "Verify and retain"}
      </button>
    </div>}
  </section>;
}
