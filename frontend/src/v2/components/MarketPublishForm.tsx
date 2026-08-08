import { useEffect, useMemo, useState } from "react";

import { listResourceProfiles } from "../api";

import type {
  AnnounceTaskInput,
  MarketResourceInput,
  PublishMarketOfferInput,
  ResourceProfileSummary,
} from "../types-v2";

type PublishMode = "task" | "product" | "service" | "exchange";

export type MarketPublication =
  | { kind: "task"; body: AnnounceTaskInput }
  | { kind: "offer"; body: PublishMarketOfferInput };

interface Props {
  busy: boolean;
  onCancel: () => void;
  onPublish: (publication: MarketPublication) => Promise<void>;
}

type ProfileValues = Record<string, string | boolean>;

interface ProfileEditorProps {
  prefix: "Provided" | "Requested";
  profile: ResourceProfileSummary;
  values: ProfileValues;
  communityCategory: string;
  onValues: (next: ProfileValues) => void;
  onCommunityCategory: (next: string) => void;
}

function initialProfileValues(profile: ResourceProfileSummary): ProfileValues {
  return Object.fromEntries(Object.entries(profile.schema.properties).map(([name, property]) => [
    name,
    property.enum.length > 0
      ? String(property.enum[0])
      : property.type === "boolean" ? false : "",
  ]));
}

function buildProfileAttributes(
  profile: ResourceProfileSummary,
  values: ProfileValues,
  communityCategory: string,
): Record<string, unknown> {
  const attributes: Record<string, unknown> = {};
  for (const [name, property] of Object.entries(profile.schema.properties)) {
    const raw = values[name];
    if (property.type === "boolean") {
      const value = raw === true || raw === "true";
      if (property.enum.length > 0 && !property.enum.includes(value)) {
        throw new Error(`${name} is outside the Profile enum.`);
      }
      attributes[name] = value;
      continue;
    }
    const text = typeof raw === "string" ? raw : "";
    if (!text && !property.required) continue;
    if (!text) throw new Error(`${name} is required by the selected Resource Profile.`);
    const value = property.type === "integer" ? Number(text) : text;
    if (property.type === "integer" && !Number.isSafeInteger(value)) {
      throw new Error(`${name} must be a safe integer.`);
    }
    if (property.enum.length > 0 && !property.enum.includes(value)) {
      throw new Error(`${name} is outside the Profile enum.`);
    }
    attributes[name] = value;
  }
  if (communityCategory) attributes.community_category = communityCategory;
  return attributes;
}

function parseManualProfileAttributes(value: string): Record<string, unknown> {
  let parsed: unknown;
  try {
    parsed = JSON.parse(value || "{}");
  } catch {
    throw new Error("Resource Profile attributes must be valid JSON.");
  }
  if (typeof parsed !== "object" || parsed === null || Array.isArray(parsed)) {
    throw new Error("Resource Profile attributes must be a JSON object.");
  }
  return parsed as Record<string, unknown>;
}

function ProfileEditor({
  prefix,
  profile,
  values,
  communityCategory,
  onValues,
  onCommunityCategory,
}: ProfileEditorProps) {
  return <div className="market-profile-editor wide">
    <p className="muted">{profile.summary}</p>
    {Object.entries(profile.schema.properties).map(([name, property]) => {
      const label = `${prefix} ${name}${property.required ? " *" : ""}`;
      if (property.type === "boolean") {
        return <label key={name} className="market-publish-toggle">
          <input
            type="checkbox"
            checked={values[name] === true || values[name] === "true"}
            onChange={(event) => onValues({ ...values, [name]: event.target.checked })}
          /> {label}
        </label>;
      }
      if (property.enum.length > 0) {
        return <label key={name}>{label}<select
          value={String(values[name] ?? "")}
          onChange={(event) => onValues({ ...values, [name]: event.target.value })}
        >{property.enum.map((item) => <option key={String(item)} value={String(item)}>{String(item)}</option>)}</select></label>;
      }
      return <label key={name}>{label}<input
        inputMode={property.type === "integer" ? "numeric" : undefined}
        value={String(values[name] ?? "")}
        onChange={(event) => onValues({ ...values, [name]: event.target.value })}
        title={property.description}
      /></label>;
    })}
    {profile.category_mappings.length > 0 && <label>{prefix} community category<select
      value={communityCategory}
      onChange={(event) => onCommunityCategory(event.target.value)}
    >
      <option value="">No community category hint</option>
      {profile.category_mappings.map((mapping) => <option
        key={mapping.community_category}
        value={mapping.community_category}
      >{mapping.community_category} to {mapping.market_category}</option>)}
    </select></label>}
  </div>;
}

function newIdempotencyKey(): string {
  const bytes = new Uint8Array(16);
  crypto.getRandomValues(bytes);
  return Array.from(bytes, (value) => value.toString(16).padStart(2, "0")).join("");
}

function commaValues(value: string): string[] {
  return Array.from(new Set(
    value.split(",").map((item) => item.trim()).filter(Boolean),
  )).sort();
}

function canonicalResourceId(value: string, idempotencyKey: string): string {
  const trimmed = value.trim();
  if (/^[a-z][a-z0-9+.-]{0,31}:[^\s]+$/.test(trimmed)) return trimmed;
  const slug = trimmed.toLowerCase().replace(/[^a-z0-9]+/g, "-").replace(/^-|-$/g, "");
  return `urn:nthdao:resource:${slug || idempotencyKey.slice(0, 16)}`;
}

function categoryForMode(mode: PublishMode): MarketResourceInput["category"] {
  if (mode === "product") return "products";
  if (mode === "service") return "services";
  return "other";
}

function typeForMode(mode: PublishMode): string {
  if (mode === "product") return "product";
  if (mode === "service") return "service";
  return "resource";
}

function publicFieldRisk(values: string[]): string {
  const text = values.join("\n");
  if (/\b[A-Z]:[\\/]Users[\\/][^\\/\s]+[\\/]/i.test(text)
    || /\/(?:Users|home)\/[^/\s]+\//.test(text)
    || /\bfile:\/\//i.test(text)) {
    return "Remove local file paths. Market fields are public, signed, and may be federated.";
  }
  if (/-----BEGIN (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----/.test(text)
    || /\bgh[pousr]_[A-Za-z0-9]{20,}\b/.test(text)
    || /\bsk-(?:ant-)?[A-Za-z0-9_-]{32,}\b/.test(text)) {
    return "Remove credentials or private-key material from public Market fields.";
  }
  return "";
}

export function MarketPublishForm({ busy, onCancel, onPublish }: Props) {
  const [mode, setMode] = useState<PublishMode>("task");
  const [title, setTitle] = useState("");
  const [summary, setSummary] = useState("");
  const [capabilities, setCapabilities] = useState("");
  const [taskCategory, setTaskCategory] = useState("general");
  const [rewardMinor, setRewardMinor] = useState("0");
  const [rewardAsset, setRewardAsset] = useState("credit");
  const [provideCategory, setProvideCategory] = useState<MarketResourceInput["category"]>("other");
  const [provideType, setProvideType] = useState("resource");
  const [provideReference, setProvideReference] = useState("");
  const [provideQuantity, setProvideQuantity] = useState("1");
  const [provideUnit, setProvideUnit] = useState("item");
  const [askReturn, setAskReturn] = useState(false);
  const [requestCategory, setRequestCategory] = useState<MarketResourceInput["category"]>("digital-assets");
  const [requestType, setRequestType] = useState("digital-asset");
  const [requestReference, setRequestReference] = useState("");
  const [requestQuantity, setRequestQuantity] = useState("1");
  const [requestUnit, setRequestUnit] = useState("unit");
  const [profileRuleId, setProfileRuleId] = useState("");
  const [profileDigest, setProfileDigest] = useState("");
  const [requestProfileRuleId, setRequestProfileRuleId] = useState("");
  const [requestProfileDigest, setRequestProfileDigest] = useState("");
  const [tradeRuleId, setTradeRuleId] = useState("");
  const [tradeRuleDigest, setTradeRuleDigest] = useState("");
  const [localProfiles, setLocalProfiles] = useState<ResourceProfileSummary[]>([]);
  const [profileLoadError, setProfileLoadError] = useState("");
  const [profileValues, setProfileValues] = useState<ProfileValues>({});
  const [requestProfileValues, setRequestProfileValues] = useState<ProfileValues>({});
  const [profileCommunityCategory, setProfileCommunityCategory] = useState("");
  const [requestProfileCommunityCategory, setRequestProfileCommunityCategory] = useState("");
  const [manualProfileAttributes, setManualProfileAttributes] = useState("{}");
  const [manualRequestProfileAttributes, setManualRequestProfileAttributes] = useState("{}");
  const [idempotencyKey] = useState(newIdempotencyKey);
  const [error, setError] = useState("");

  const needsRequest = mode === "exchange" || askReturn;
  const selectedProfile = useMemo(
    () => localProfiles.find((profile) => (
      profile.digest === profileDigest && profile.profile_id === profileRuleId
    )),
    [localProfiles, profileDigest, profileRuleId],
  );
  const selectedRequestProfile = useMemo(
    () => localProfiles.find((profile) => (
      profile.digest === requestProfileDigest && profile.profile_id === requestProfileRuleId
    )),
    [localProfiles, requestProfileDigest, requestProfileRuleId],
  );

  useEffect(() => {
    const controller = new AbortController();
    async function loadProfiles() {
      const profiles: ResourceProfileSummary[] = [];
      const seenCursors = new Set<string>();
      let cursor = "";
      while (true) {
        const page = await listResourceProfiles(controller.signal, cursor, 200);
        profiles.push(...page.items.filter((profile) => profile.active));
        if (!page.next_cursor) break;
        if (seenCursors.has(page.next_cursor)) {
          throw new Error("Resource Profile pagination returned a repeated cursor.");
        }
        if (profiles.length >= 4_096) {
          setProfileLoadError(
            "Only the first 4,096 active Resource Profiles are available in this form.",
          );
          break;
        }
        seenCursors.add(page.next_cursor);
        cursor = page.next_cursor;
      }
      setLocalProfiles(profiles);
    }
    loadProfiles()
      .catch((reason) => {
        if (reason instanceof DOMException && reason.name === "AbortError") return;
        setProfileLoadError(reason instanceof Error ? reason.message : String(reason));
      });
    return () => controller.abort();
  }, []);

  function selectLocalProfile(digest: string, requested: boolean) {
    const profile = localProfiles.find((item) => item.digest === digest);
    const setId = requested ? setRequestProfileRuleId : setProfileRuleId;
    const setDigest = requested ? setRequestProfileDigest : setProfileDigest;
    const setValues = requested ? setRequestProfileValues : setProfileValues;
    const setCommunity = requested
      ? setRequestProfileCommunityCategory
      : setProfileCommunityCategory;
    if (!profile) {
      setId("");
      setDigest("");
      setValues({});
      setCommunity("");
      return;
    }
    setId(profile.profile_id);
    setDigest(profile.digest);
    setValues(initialProfileValues(profile));
    setCommunity(profile.category_mappings[0]?.community_category ?? "");
    if (requested) setRequestType(profile.resource_types[0] ?? requestType);
    else setProvideType(profile.resource_types[0] ?? provideType);
  }

  function selectMode(next: PublishMode) {
    setMode(next);
    setError("");
    if (next !== "task") {
      setProvideCategory(categoryForMode(next));
      setProvideType(typeForMode(next));
      setProvideUnit(next === "service" ? "job" : "item");
      setAskReturn(next === "exchange");
    }
  }

  async function submit(event: React.FormEvent) {
    event.preventDefault();
    setError("");
    if (!title.trim()) {
      setError("Title is required.");
      return;
    }
    const privacyRisk = publicFieldRisk([
      title,
      summary,
      capabilities,
      provideReference,
      requestReference,
    ]);
    if (privacyRisk) {
      setError(privacyRisk);
      return;
    }
    if (commaValues(capabilities).some((value) => value.length > 100)) {
      setError("Capability names must not exceed 100 characters.");
      return;
    }
    if (commaValues(capabilities).length > 32) {
      setError("No more than 32 capabilities may be published.");
      return;
    }
    if (mode === "task") {
      const reward = Number(rewardMinor);
      if (!Number.isSafeInteger(reward) || reward < 0) {
        setError("Bounty must be a non-negative integer in minor units.");
        return;
      }
      await onPublish({
        kind: "task",
        body: {
          title: title.trim(),
          listing_type: "task",
          description: summary.trim(),
          capability_set: commaValues(capabilities),
          reward_minor: reward,
          reward_asset: rewardAsset.trim() || "credit",
          context: taskCategory.trim() || "general",
        },
      });
      return;
    }
    if (!provideReference.trim()) {
      setError("Offered resource is required.");
      return;
    }
    if (needsRequest && !requestReference.trim()) {
      setError("Requested resource is required for an exchange.");
      return;
    }
    if (Boolean(profileRuleId.trim()) !== Boolean(profileDigest.trim())) {
      setError("Provided Resource Profile Skill ID and digest must be supplied together.");
      return;
    }
    if (
      needsRequest
      && Boolean(requestProfileRuleId.trim()) !== Boolean(requestProfileDigest.trim())
    ) {
      setError("Requested Resource Profile Skill ID and digest must be supplied together.");
      return;
    }
    if (Boolean(tradeRuleId.trim()) !== Boolean(tradeRuleDigest.trim())) {
      setError("Trade Skill ID and digest must be supplied together.");
      return;
    }

    const profile = {
      ...(profileRuleId.trim() ? { profile_rule_id: profileRuleId.trim() } : {}),
      ...(profileDigest.trim() ? { profile_digest: profileDigest.trim() } : {}),
    };
    const requestProfile = {
      ...(requestProfileRuleId.trim()
        ? { profile_rule_id: requestProfileRuleId.trim() }
        : {}),
      ...(requestProfileDigest.trim()
        ? { profile_digest: requestProfileDigest.trim() }
        : {}),
    };
    let providedAttributes: Record<string, unknown>;
    let requestedAttributes: Record<string, unknown>;
    try {
      providedAttributes = selectedProfile
        ? buildProfileAttributes(selectedProfile, profileValues, profileCommunityCategory)
        : profileRuleId.trim()
          ? parseManualProfileAttributes(manualProfileAttributes)
          : { display_reference: provideReference.trim() };
      requestedAttributes = selectedRequestProfile
        ? buildProfileAttributes(
          selectedRequestProfile,
          requestProfileValues,
          requestProfileCommunityCategory,
        )
        : requestProfileRuleId.trim()
          ? parseManualProfileAttributes(manualRequestProfileAttributes)
          : { display_reference: requestReference.trim() };
    } catch (reason) {
      setError(reason instanceof Error ? reason.message : String(reason));
      return;
    }
    const provides: MarketResourceInput[] = [{
      leg_id: "provide-1",
      category: provideCategory,
      resource_type: provideType.trim(),
      resource_id: canonicalResourceId(provideReference, idempotencyKey),
      quantity: provideQuantity.trim(),
      unit: provideUnit.trim(),
      ...profile,
      attributes: providedAttributes,
    }];
    const requests: MarketResourceInput[] = needsRequest ? [{
      leg_id: "request-1",
      category: requestCategory,
      resource_type: requestType.trim(),
      resource_id: canonicalResourceId(requestReference, idempotencyKey),
      quantity: requestQuantity.trim(),
      unit: requestUnit.trim(),
      ...requestProfile,
      attributes: requestedAttributes,
    }] : [];
    await onPublish({
      kind: "offer",
      body: {
        idempotency_key: idempotencyKey,
        intent: needsRequest ? "exchange" : "provide",
        category: provideCategory,
        title: title.trim(),
        summary: summary.trim(),
        provides,
        requests,
        rule_refs: tradeRuleId.trim() ? [{
          rule_id: tradeRuleId.trim(),
          digest: tradeRuleDigest.trim(),
        }] : [],
        capability_set: commaValues(capabilities),
        offer_validity_seconds: 30 * 24 * 60 * 60,
        discovery_ttl_seconds: 24 * 60 * 60,
      },
    });
  }

  return <form className="commerce-form market-publish-form" aria-label="Publish to NTH DAO" onSubmit={submit}>
    <div className="market-publish-heading">
      <div><p className="main-eyebrow">One entry, explicit protocol</p><h2>Publish to NTH DAO</h2></div>
      <button type="button" className="btn btn-secondary" onClick={onCancel}>Cancel</button>
    </div>
    <div className="market-publish-modes" role="tablist" aria-label="Publication type">
      {([[
        "task", "Task", "Request work that can be claimed into a Mission",
      ], [
        "product", "Product", "Offer a physical or digital product",
      ], [
        "service", "Service", "Offer human or Agent capability",
      ], [
        "exchange", "Exchange", "Swap any resource for another resource",
      ]] as Array<[PublishMode, string, string]>).map(([value, label, help]) => <button
        key={value}
        type="button"
        role="tab"
        aria-selected={mode === value}
        className={mode === value ? "active" : ""}
        onClick={() => selectMode(value)}
      ><strong>{label}</strong><span>{help}</span></button>)}
    </div>

    <div className="commerce-form-grid">
      <label>Title<input value={title} onChange={(event) => setTitle(event.target.value)} required maxLength={160} /></label>
      <label>Capabilities<input value={capabilities} onChange={(event) => setCapabilities(event.target.value)} placeholder="code-review, translation" maxLength={512} /></label>
      <label className="wide">Description<textarea value={summary} onChange={(event) => setSummary(event.target.value)} maxLength={2000} /></label>
    </div>

    {mode === "task" ? <div className="commerce-form-grid market-publish-section">
      <label>Task category<input value={taskCategory} onChange={(event) => setTaskCategory(event.target.value)} maxLength={64} /></label>
      <label>Bounty asset<input value={rewardAsset} onChange={(event) => setRewardAsset(event.target.value)} maxLength={32} /></label>
      <label>Bounty amount (minor units)<input inputMode="numeric" value={rewardMinor} onChange={(event) => setRewardMinor(event.target.value)} /></label>
      <p className="muted wide">Claiming a Task creates or links one Mission. A bounty is a signed term, not proof of available funds.</p>
    </div> : <>
      <div className="market-publish-section">
        <h3>What you provide</h3>
        <div className="commerce-form-grid">
          {mode === "exchange" && <label>Broad category<select value={provideCategory} onChange={(event) => setProvideCategory(event.target.value as MarketResourceInput["category"])}>
            <option value="products">Product</option><option value="services">Service</option><option value="digital-assets">Digital asset</option><option value="other">Other</option>
          </select></label>}
          <label>Resource type<input value={provideType} onChange={(event) => setProvideType(event.target.value)} required maxLength={128} /></label>
          <label className="wide">Offered resource<input value={provideReference} onChange={(event) => setProvideReference(event.target.value)} placeholder="Name, SKU, DID, token address, or urn:..." required maxLength={512} /></label>
          <label>Quantity<input value={provideQuantity} onChange={(event) => setProvideQuantity(event.target.value)} required maxLength={80} /></label>
          <label>Unit<input value={provideUnit} onChange={(event) => setProvideUnit(event.target.value)} required maxLength={64} /></label>
        </div>
      </div>
      {mode !== "exchange" && <label className="market-publish-toggle"><input type="checkbox" checked={askReturn} onChange={(event) => setAskReturn(event.target.checked)} /> Ask for something in return</label>}
      {needsRequest && <div className="market-publish-section">
        <h3>What you request</h3>
        <div className="commerce-form-grid">
          <label>Broad category<select value={requestCategory} onChange={(event) => setRequestCategory(event.target.value as MarketResourceInput["category"])}>
            <option value="products">Product</option><option value="services">Service</option><option value="digital-assets">Digital asset</option><option value="other">Other</option>
          </select></label>
          <label>Resource type<input value={requestType} onChange={(event) => setRequestType(event.target.value)} required maxLength={128} /></label>
          <label className="wide">Requested resource<input value={requestReference} onChange={(event) => setRequestReference(event.target.value)} placeholder="Asset, service, product, token address, or urn:..." required maxLength={512} /></label>
          <label>Quantity<input value={requestQuantity} onChange={(event) => setRequestQuantity(event.target.value)} required maxLength={80} /></label>
          <label>Unit<input value={requestUnit} onChange={(event) => setRequestUnit(event.target.value)} required maxLength={64} /></label>
        </div>
      </div>}
      <details className="market-publish-advanced">
        <summary>Optional Skills and exact digests</summary>
        <div className="commerce-form-grid">
          <label className="wide">Use local Profile for provided resource<select
            aria-label="Provided local Resource Profile"
            value={selectedProfile?.digest ?? ""}
            onChange={(event) => selectLocalProfile(event.target.value, false)}
          ><option value="">Manual reference or none</option>{localProfiles.map((profile) => <option
            key={profile.digest}
            value={profile.digest}
          >{profile.profile_id} v{profile.version}{profile.recognized ? " (recognized)" : " (verified)"}</option>)}</select></label>
          <label>Provided Resource Profile Skill ID<input value={profileRuleId} onChange={(event) => setProfileRuleId(event.target.value)} placeholder="org.example.profile/item" maxLength={190} /></label>
          <label>Provided Resource Profile digest<input value={profileDigest} onChange={(event) => setProfileDigest(event.target.value)} placeholder="sha256:..." maxLength={71} /></label>
          {selectedProfile
            ? <ProfileEditor
              prefix="Provided"
              profile={selectedProfile}
              values={profileValues}
              communityCategory={profileCommunityCategory}
              onValues={setProfileValues}
              onCommunityCategory={setProfileCommunityCategory}
            />
            : profileRuleId.trim() && <label className="wide">Provided Profile attributes JSON<textarea
              value={manualProfileAttributes}
              onChange={(event) => setManualProfileAttributes(event.target.value)}
              rows={4}
              maxLength={16_384}
            /></label>}
          {needsRequest && <>
            <label className="wide">Use local Profile for requested resource<select
              aria-label="Requested local Resource Profile"
              value={selectedRequestProfile?.digest ?? ""}
              onChange={(event) => selectLocalProfile(event.target.value, true)}
            ><option value="">Manual reference or none</option>{localProfiles.map((profile) => <option
              key={profile.digest}
              value={profile.digest}
            >{profile.profile_id} v{profile.version}{profile.recognized ? " (recognized)" : " (verified)"}</option>)}</select></label>
            <label>Requested Resource Profile Skill ID<input value={requestProfileRuleId} onChange={(event) => setRequestProfileRuleId(event.target.value)} placeholder="org.example.profile/payment" maxLength={190} /></label>
            <label>Requested Resource Profile digest<input value={requestProfileDigest} onChange={(event) => setRequestProfileDigest(event.target.value)} placeholder="sha256:..." maxLength={71} /></label>
            {selectedRequestProfile
              ? <ProfileEditor
                prefix="Requested"
                profile={selectedRequestProfile}
                values={requestProfileValues}
                communityCategory={requestProfileCommunityCategory}
                onValues={setRequestProfileValues}
                onCommunityCategory={setRequestProfileCommunityCategory}
              />
              : requestProfileRuleId.trim() && <label className="wide">Requested Profile attributes JSON<textarea
                value={manualRequestProfileAttributes}
                onChange={(event) => setManualRequestProfileAttributes(event.target.value)}
                rows={4}
                maxLength={16_384}
              /></label>}
          </>}
          <label>Trade Skill ID<input value={tradeRuleId} onChange={(event) => setTradeRuleId(event.target.value)} placeholder="org.example.rules/delivery" maxLength={160} /></label>
          <label>Trade Skill digest<input value={tradeRuleDigest} onChange={(event) => setTradeRuleDigest(event.target.value)} placeholder="sha256:..." maxLength={71} /></label>
        </div>
        {profileLoadError && <p className="trade-proposal-warning">Local Resource Profiles unavailable: {profileLoadError}</p>}
      </details>
      <p className="trade-proposal-warning">The node signs a discovery claim and exact resource descriptors. Skills are references, not trusted code. Real-money and irreversible execution remain disabled.</p>
    </>}

    {error && <p className="trade-proposal-warning" role="alert">{error}</p>}
    <div className="commerce-form-actions"><button className="btn btn-primary" disabled={busy}>{busy ? "Publishing..." : "Publish"}</button></div>
  </form>;
}
