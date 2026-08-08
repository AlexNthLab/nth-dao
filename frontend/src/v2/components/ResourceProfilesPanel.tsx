import { useEffect, useState } from "react";
import {
  importResourceProfile,
  listResourceProfiles,
  setResourceProfileRecognition,
} from "../api";
import type { ResourceProfileSummary } from "../types-v2";
import { useToast } from "./Toast";


const recognitionKeys = new Map<string, string>();


function short(value: string, size = 28): string {
  return value.length <= size
    ? value
    : `${value.slice(0, size - 7)}...${value.slice(-4)}`;
}


function pendingRecognitionKey(digest: string, accepted: boolean): string {
  const storageKey = `nth-resource-profile:${digest}:${accepted ? "accept" : "revoke"}`;
  try {
    const stored = sessionStorage.getItem(storageKey);
    if (stored) {
      recognitionKeys.set(storageKey, stored);
      return stored;
    }
  } catch {
    // Privacy modes may disable sessionStorage; retain retry safety in memory.
  }
  const existing = recognitionKeys.get(storageKey);
  if (existing) return existing;
  const created = `profile-recognition:${crypto.randomUUID()}`;
  recognitionKeys.set(storageKey, created);
  try {
    sessionStorage.setItem(storageKey, created);
  } catch {
    // In-memory retry remains available for this page lifetime.
  }
  return created;
}


function clearRecognitionKey(digest: string, accepted: boolean): void {
  const storageKey = `nth-resource-profile:${digest}:${accepted ? "accept" : "revoke"}`;
  recognitionKeys.delete(storageKey);
  try {
    sessionStorage.removeItem(storageKey);
  } catch {
    // No persistent storage was available, so there is nothing else to clear.
  }
}


export function ResourceProfilesPanel() {
  const toast = useToast();
  const [profiles, setProfiles] = useState<ResourceProfileSummary[]>([]);
  const [total, setTotal] = useState(0);
  const [nextCursor, setNextCursor] = useState("");
  const [pageBusy, setPageBusy] = useState(false);
  const [warning, setWarning] = useState("");
  const [documentText, setDocumentText] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");

  async function refresh(signal?: AbortSignal, cursor = "", append = false) {
    const page = await listResourceProfiles(signal, cursor, 100);
    for (const profile of page.items) {
      clearRecognitionKey(profile.digest, profile.recognized);
    }
    setProfiles((current) => append ? [...current, ...page.items] : page.items);
    setTotal(page.count);
    setNextCursor(page.next_cursor);
    setWarning(page.warning);
  }

  async function loadMore() {
    if (!nextCursor || pageBusy) return;
    setPageBusy(true);
    setError("");
    try {
      await refresh(undefined, nextCursor, true);
    } catch (reason) {
      setError(reason instanceof Error ? reason.message : String(reason));
    } finally {
      setPageBusy(false);
    }
  }

  useEffect(() => {
    const controller = new AbortController();
    refresh(controller.signal).catch((reason) => {
      if (reason instanceof DOMException && reason.name === "AbortError") return;
      setError(reason instanceof Error ? reason.message : String(reason));
    });
    return () => controller.abort();
  }, []);

  async function handleImport(event: React.FormEvent) {
    event.preventDefault();
    if (!documentText.trim() || busy) return;
    let document: unknown;
    try {
      document = JSON.parse(documentText);
    } catch {
      setError("Profile document must be valid JSON.");
      return;
    }
    if (typeof document !== "object" || document === null || Array.isArray(document)) {
      setError("Profile document must be a JSON object.");
      return;
    }
    setBusy(true);
    setError("");
    try {
      const result = await importResourceProfile(document as Record<string, unknown>);
      setDocumentText("");
      await refresh();
      toast.push(
        result.installed ? "Signed Resource Profile imported" : "Resource Profile already cached",
        "success",
      );
    } catch (reason) {
      setError(reason instanceof Error ? reason.message : String(reason));
    } finally {
      setBusy(false);
    }
  }

  async function handleRecognition(profile: ResourceProfileSummary) {
    if (busy) return;
    const accepted = !profile.recognized;
    const idempotencyKey = pendingRecognitionKey(profile.digest, accepted);
    setBusy(true);
    setError("");
    try {
      const result = await setResourceProfileRecognition(
        profile.digest,
        accepted,
        idempotencyKey,
      );
      clearRecognitionKey(profile.digest, accepted);
      setProfiles((current) => current.map((item) => (
        item.digest === profile.digest ? result.profile : item
      )));
      toast.push(
        profile.recognized ? "Resource Profile recognition revoked" : "Resource Profile recognized locally",
        "success",
      );
    } catch (reason) {
      setError(reason instanceof Error ? reason.message : String(reason));
    } finally {
      setBusy(false);
    }
  }

  return <section className="resource-profile-panel" aria-label="Resource Profile Skills">
    <div className="resource-profile-heading">
      <div>
        <strong>Resource Profile Skills</strong>
        <p className="muted">Signed schemas describe resources. Recognition remains local.</p>
      </div>
      <span className="pill dim">{profiles.length} of {total} local</span>
    </div>
    {warning && <p className="trade-proposal-warning">{warning}</p>}
    {error && <p className="danger-text" role="alert">{error}</p>}
    <details className="market-publish-advanced">
      <summary>Import signed Profile JSON</summary>
      <form onSubmit={handleImport} className="resource-profile-import">
        <textarea
          aria-label="Signed Resource Profile JSON"
          value={documentText}
          onChange={(event) => setDocumentText(event.target.value)}
          maxLength={262_144}
          rows={7}
          placeholder='{"kind":"org.nthdao.resource-profile",...}'
          disabled={busy}
        />
        <button className="btn btn-secondary" type="submit" disabled={busy || !documentText.trim()}>
          {busy ? "Verifying..." : "Verify and import"}
        </button>
      </form>
    </details>
    <div className="resource-profile-list">
      {profiles.map((profile) => <div className="resource-profile-row" key={profile.digest}>
        <div>
          <strong>{profile.profile_id}</strong>
          <span className="muted">v{profile.version} / {profile.active_reason}</span>
          <code title={profile.publisher_did}>{short(profile.publisher_did)}</code>
        </div>
        <div className="resource-profile-actions">
          <span className={`pill ${profile.recognized ? "ok" : "wait"}`}>
            {profile.recognized ? "Recognized locally" : "Verified only"}
          </span>
          <button
            type="button"
            className="btn btn-ghost"
            disabled={busy}
            onClick={() => void handleRecognition(profile)}
          >{profile.recognized ? "Revoke" : "Recognize"}</button>
        </div>
      </div>)}
      {profiles.length === 0 && <p className="muted">No signed Resource Profiles are cached locally.</p>}
      {nextCursor && <button
        type="button"
        className="btn btn-ghost"
        disabled={pageBusy || busy}
        onClick={() => void loadMore()}
      >{pageBusy ? "Loading..." : "Load more"}</button>}
    </div>
  </section>;
}
