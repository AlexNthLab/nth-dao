/**
 * Topbar — brand, identity slug, Cmd+K trigger.
 *
 * 48px tall, single row. The identity slug is the user's stable
 * anchor across the whole UI ("this is you signing"). The Cmd+K
 * hint stays visible always so the keyboard contract is taught
 * passively.
 */

import { BrandLogo } from "./BrandLogo";
import { BrandMark } from "./BrandMark";
import type { IdentityHeader } from "../types-v2";

export interface TopbarProps {
  identity: IdentityHeader | null;
  onCmdK: () => void;
}

export function Topbar({ identity, onCmdK }: TopbarProps) {
  return (
    <header className="topbar">
      <div className="topbar-brand">
        <BrandLogo size={24} className="topbar-logo-mark" />
        <BrandMark />
      </div>

      {identity && (
        <div className="topbar-identity" title={identity.did}>
          <strong>{identity.agent_id}</strong>
          <code>{identity.code}</code>
        </div>
      )}

      <div className="topbar-spacer" />

      <button type="button" className="cmdk-trigger" onClick={onCmdK}>
        <span>Search or command</span>
        <kbd>⌘K</kbd>
      </button>
    </header>
  );
}
