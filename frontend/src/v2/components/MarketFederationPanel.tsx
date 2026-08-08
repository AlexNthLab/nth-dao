import { useEffect, useRef, useState } from "react";
import {
  discoverFederationPeers,
  getFederationStatus,
  refreshFederation,
  updateFederationPeer,
} from "../api";
import type { FederationStatus } from "../types-v2";
import { relativeTimeShort } from "../utils/time";
import { useToast } from "./Toast";

interface MarketFederationPanelProps {
  actorId?: string;
  onUpdated?: () => void;
}

function formatFederationRefresh(ms: number): string {
  if (!Number.isFinite(ms) || ms <= 0) return "Never";
  try {
    return relativeTimeShort(new Date(ms).toISOString());
  } catch {
    return "Unknown";
  }
}

export function MarketFederationPanel({
  actorId = "admin",
  onUpdated,
}: MarketFederationPanelProps) {
  const toast = useToast();
  const [status, setStatus] = useState<FederationStatus | null>(null);
  const [peerUrl, setPeerUrl] = useState("");
  const [busy, setBusy] = useState(false);
  const requestSequence = useRef(0);

  function beginRequest(): number {
    requestSequence.current += 1;
    return requestSequence.current;
  }

  function commitStatus(sequence: number, next: FederationStatus): boolean {
    if (sequence !== requestSequence.current) return false;
    setStatus(next);
    return true;
  }

  useEffect(() => {
    let cancelled = false;
    let discoveryCommitted = false;
    const controller = new AbortController();
    const sequence = beginRequest();
    getFederationStatus(controller.signal)
      .then((next) => {
        if (cancelled || discoveryCommitted) return;
        commitStatus(sequence, next);
      })
      .catch(() => {
        // Federation diagnostics are optional; Market remains locally usable.
      });
    discoverFederationPeers({
      actorId,
      timeoutSeconds: 1.25,
      add: false,
      refresh: false,
    }).then((next) => {
      if (cancelled || !commitStatus(sequence, next)) return;
      discoveryCommitted = true;
      if (
        (next.imported_peers?.length ?? 0) > 0
        || (next.identity_verified_peers?.length ?? 0) > 0
      ) onUpdated?.();
    }).catch(() => {
      // LAN/mDNS discovery is best-effort and must not block local Market use.
    });
    return () => {
      cancelled = true;
      controller.abort();
    };
  }, [actorId]);

  async function handleRefresh() {
    if (busy) return;
    setBusy(true);
    const sequence = beginRequest();
    try {
      const next = await refreshFederation();
      if (!commitStatus(sequence, next)) return;
      onUpdated?.();
      toast.push("Federation refreshed", "success");
    } catch (error) {
      toast.push(
        `Federation refresh failed: ${error instanceof Error ? error.message : String(error)}`,
        "error",
      );
    } finally {
      setBusy(false);
    }
  }

  async function handleDiscover() {
    if (busy) return;
    setBusy(true);
    const sequence = beginRequest();
    try {
      const next = await discoverFederationPeers({
        actorId,
        timeoutSeconds: 2,
        add: false,
        refresh: false,
      });
      if (!commitStatus(sequence, next)) return;
      onUpdated?.();
      const imported = next.imported_peers?.length ?? 0;
      const skipped = next.skipped_peers?.length ?? 0;
      const verified = next.identity_verified_peers?.length ?? 0;
      const errors = next.discovery_errors?.length ?? 0;
      if (verified > 0) {
        toast.push(`${verified} nearby DAO peer${verified === 1 ? "" : "s"} verified; approve below to sync`, "info");
      } else if (skipped > 0) {
        toast.push("Nearby nodes found, but none passed identity/federation verification", "warn");
      } else {
        toast.push(
          errors > 0 ? "Discovery finished with backend warnings" : "No nearby DAO peers found",
          errors > 0 ? "warn" : "info",
        );
      }
    } catch (error) {
      toast.push(
        `Federation discovery failed: ${error instanceof Error ? error.message : String(error)}`,
        "error",
      );
    } finally {
      setBusy(false);
    }
  }

  async function addApprovedPeer(peer: string) {
    if (!peer || busy) return;
    setBusy(true);
    const sequence = beginRequest();
    try {
      const saved = await updateFederationPeer(peer, "add");
      if (!commitStatus(sequence, saved)) return;
      setPeerUrl("");
      try {
        const refreshed = await refreshFederation();
        commitStatus(sequence, refreshed);
      } catch (error) {
        toast.push(
          `Peer saved, refresh failed: ${error instanceof Error ? error.message : String(error)}`,
          "warn",
        );
      }
      onUpdated?.();
      toast.push("Federation peer added", "success");
    } catch (error) {
      toast.push(
        `Add peer failed: ${error instanceof Error ? error.message : String(error)}`,
        "error",
      );
    } finally {
      setBusy(false);
    }
  }

  async function handleAddPeer(event: React.FormEvent) {
    event.preventDefault();
    await addApprovedPeer(peerUrl.trim());
  }

  async function handleRemovePeer(peer: string) {
    if (!peer || busy) return;
    setBusy(true);
    const sequence = beginRequest();
    try {
      const removed = await updateFederationPeer(peer, "remove");
      if (!commitStatus(sequence, removed)) return;
      try {
        const refreshed = await refreshFederation();
        commitStatus(sequence, refreshed);
      } catch (error) {
        toast.push(
          `Peer removed, refresh failed: ${error instanceof Error ? error.message : String(error)}`,
          "warn",
        );
      }
      onUpdated?.();
      toast.push("Federation peer removed", "success");
    } catch (error) {
      toast.push(
        `Remove peer failed: ${error instanceof Error ? error.message : String(error)}`,
        "error",
      );
    } finally {
      setBusy(false);
    }
  }

  return <section className="market-federation-panel" aria-label="Market federation">
    <div className="market-federation-heading">
      <strong>Federation</strong>
      <span className="pill dim">{status?.cached_announcements ?? 0} remote</span>
    </div>
    <p className="muted">
      {status?.peers.length
        ? "Verified peers exchange signed Market discovery claims."
        : "Add a reachable DAO URL or scan the LAN to discover another Market."}
    </p>
    <form onSubmit={handleAddPeer} className="market-federation-add">
      <input
        aria-label="Federation peer URL"
        placeholder="http://192.168.1.20:8080"
        value={peerUrl}
        onChange={(event) => setPeerUrl(event.target.value)}
        disabled={busy}
      />
      <button type="submit" className="btn" disabled={!peerUrl.trim() || busy}>Add</button>
    </form>
    <div className="market-federation-actions">
      <button type="button" className="btn btn-ghost" disabled={busy} onClick={() => void handleRefresh()}>
        {busy ? "Syncing..." : "Refresh"}
      </button>
      <button
        type="button"
        className="btn btn-ghost"
        disabled={busy}
        onClick={() => void handleDiscover()}
        title="Scan LAN/mDNS for DAO nodes that publish HTTP federation URLs"
      >
        {busy ? "Scanning..." : "Discover nearby DAOs"}
      </button>
    </div>
    <div className="market-federation-stats">
      <span>Seeds: {status?.seed_peers?.length ?? status?.peers.length ?? 0}</span>
      <span>Learned: {Object.keys(status?.learned_peers ?? {}).length}</span>
      <span>Indexed: {status?.incremental_source_cursors ?? 0}</span>
      <span>Last: {formatFederationRefresh(status?.last_refresh_ms ?? 0)}</span>
      {status?.poller_started && <span>Poller on</span>}
    </div>
    <div className="market-federation-stats">
      <span>Reverse discovery: {status?.reverse_discovery_enabled ? "ready" : "local only"}</span>
      <span className={status?.lan_federation_ready ? "ok-text" : "warn-text"}>
        LAN federation: {status?.lan_federation_ready ? "advertising" : "not advertising"}
      </span>
    </div>
    {status?.lan_federation_configured && <div className="market-federation-stats">
      <span>UDP{status.lan_udp_port ? ` :${status.lan_udp_port}` : ""}: {status.lan_udp_publisher_active ? "active" : "inactive"}</span>
      <span>mDNS: {status.lan_mdns_publisher_active
        ? "active"
        : status.lan_mdns_available ? "inactive" : "unavailable"}</span>
    </div>}
    {status?.public_peer_url && <code title={status.public_peer_url}>{status.public_peer_url}</code>}
    {status?.lan_diagnostics?.map((diagnostic) => <p key={diagnostic} className="warn-text">{diagnostic}</p>)}
    {status?.imported_peers?.length ? <p className="ok-text">Imported: {status.imported_peers.length}</p> : null}
    {status?.identity_verified_peers?.length ? <p className="ok-text">Identity verified: {status.identity_verified_peers.length}</p> : null}
    {status?.discovered_peers?.some((peer) => peer.identity_verified && peer.federation_peer_url)
      ? <div className="market-federation-peers" aria-label="Nearby verified DAO peers">
        <p className="muted">Nearby identity proof is not trust. Approve a peer before Market sync.</p>
        {status.discovered_peers.filter(
          (peer) => peer.identity_verified && peer.federation_peer_url,
        ).map((peer) => {
          const url = peer.federation_peer_url ?? "";
          const approved = status.file_peers.includes(url);
          return <div key={`${peer.peer_did ?? peer.did}:${url}`}>
            <span>{peer.label || peer.agent_id || peer.peer_did}</span>
            <code title={url}>{url}</code>
            <button
              type="button"
              className="btn btn-ghost"
              disabled={busy || approved}
              onClick={() => void addApprovedPeer(url)}
            >{approved ? "Approved" : "Approve"}</button>
          </div>;
        })}
      </div>
      : null}
    {status?.skipped_peers?.length ? <div>
      <p className="warn-text">Peers not imported: {status.skipped_peers.length}</p>
      {status.skipped_peers.slice(0, 3).map((peer) => <p
        key={`${peer.did ?? peer.agent_id}:${peer.source_addr ?? ""}`}
        className="muted"
      >
        {peer.label || peer.agent_id || peer.did || "Unknown peer"}: {peer.identity_error || "The peer did not expose a verified federation endpoint."}
      </p>)}
    </div> : null}
    {(status?.stale_announcements ?? 0) > 0 && <p className="warn-text">
      {status?.stale_announcements} stale discovery hint(s) are visible but cannot be acted on.
    </p>}
    {status?.last_error && <p className="danger-text">{status.last_error}</p>}
    {status?.file_peers.length ? <div className="market-federation-peers">
      {status.file_peers.map((peer) => <div key={peer}>
        <code title={peer}>{peer}</code>
        <button type="button" className="btn btn-ghost" disabled={busy} onClick={() => void handleRemovePeer(peer)}>
          Remove
        </button>
      </div>)}
    </div> : null}
  </section>;
}
