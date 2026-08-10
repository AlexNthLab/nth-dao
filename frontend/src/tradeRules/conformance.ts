const MAX_SAFE_INTEGER = 9_007_199_254_740_991;
const MAX_BYTES = 262_144;
const MAX_DEPTH = 32;
const MAX_NODES = 10_000;
const MAX_STRING_BYTES = 65_536;
const MAX_KEY_BYTES = 256;

export const TRADE_RULE_MANIFEST_DOMAIN = "NTH-TRADE-RULE-MANIFEST-V1";
export const TRADE_OFFER_DOMAIN = "NTH-TRADE-OFFER-V2";
export const TRADE_RULE_RECOGNITION_DOMAIN =
  "nth-dao/trade-rule-recognition/v1";
export const TRADE_DISPUTE_STATEMENT_DOMAIN =
  "nth-dao/trade-dispute-statement/v1";
export const TRADE_DISPUTE_STATEMENT_DELIVERY_DOMAIN =
  "nth-dao/trade-dispute-statement-delivery/v1";
export const TRADE_DISPUTE_STATEMENT_ACKNOWLEDGEMENT_DOMAIN =
  "nth-dao/trade-dispute-statement-acknowledgement/v1";
const TRADE_PROPOSAL_DOMAIN = "nth-dao/trade-proposal/v1";
const TRADE_ACCEPTANCE_DOMAIN = "nth-dao/trade-acceptance/v1";
const TRADE_EXECUTION_RECEIPT_DOMAIN =
  "nth-dao/trade-execution-receipt/v1";
const TRADE_RECEIPT_REVIEW_DOMAIN = "nth-dao/trade-receipt-review/v1";

type JsonObject = { [key: string]: JsonValue };
type JsonValue = null | boolean | number | string | JsonValue[] | JsonObject;

function utf8(value: string): Uint8Array {
  return new TextEncoder().encode(value);
}

function hasLoneSurrogate(value: string): boolean {
  for (let index = 0; index < value.length; index += 1) {
    const code = value.charCodeAt(index);
    if (code >= 0xd800 && code <= 0xdbff) {
      const next = value.charCodeAt(index + 1);
      if (!(next >= 0xdc00 && next <= 0xdfff)) return true;
      index += 1;
    } else if (code >= 0xdc00 && code <= 0xdfff) {
      return true;
    }
  }
  return false;
}

function canonicalString(
  value: unknown,
  path: string,
  depth: number,
  state: { nodes: number },
  ancestors: Set<object>
): string {
  state.nodes += 1;
  if (state.nodes > MAX_NODES) throw new Error("trade JSON exceeds node limit");
  if (depth > MAX_DEPTH) throw new Error("trade JSON exceeds depth limit");

  if (value === null || typeof value === "boolean") return JSON.stringify(value);
  if (typeof value === "string") {
    if (hasLoneSurrogate(value)) throw new Error(`invalid Unicode string at ${path}`);
    if (utf8(value).byteLength > MAX_STRING_BYTES) {
      throw new Error(`string too large at ${path}`);
    }
    return JSON.stringify(value);
  }
  if (typeof value === "number") {
    if (!Number.isSafeInteger(value) || Math.abs(value) > MAX_SAFE_INTEGER) {
      throw new Error(`unsafe or non-integer number at ${path}`);
    }
    return JSON.stringify(value);
  }
  if (typeof value !== "object" || value === undefined) {
    throw new Error(`unsupported value at ${path}`);
  }

  if (ancestors.has(value)) throw new Error(`cyclic value at ${path}`);
  ancestors.add(value);
  try {
    if (Array.isArray(value)) {
      return (
        "[" +
        value
          .map((item, index) =>
            canonicalString(item, `${path}[${index}]`, depth + 1, state, ancestors)
          )
          .join(",") +
        "]"
      );
    }
    const prototype = Object.getPrototypeOf(value);
    if (prototype !== Object.prototype && prototype !== null) {
      throw new Error(`non-plain object at ${path}`);
    }
    const object = value as Record<string, unknown>;
    const ownKeys = Reflect.ownKeys(object);
    if (
      ownKeys.some((key) => typeof key !== "string") ||
      ownKeys.length !== Object.keys(object).length
    ) {
      throw new Error(`non-string key at ${path}`);
    }
    const keys = Object.keys(object).sort();
    for (const key of keys) {
      if (
        key.length === 0 ||
        key.length > MAX_KEY_BYTES ||
        [...key].some((character) => {
          const code = character.charCodeAt(0);
          return code < 0x21 || code > 0x7e;
        })
      ) {
        throw new Error(`invalid ASCII key at ${path}`);
      }
    }
    return (
      "{" +
      keys
        .map(
          (key) =>
            `${JSON.stringify(key)}:${canonicalString(
              object[key],
              `${path}.${key}`,
              depth + 1,
              state,
              ancestors
            )}`
        )
        .join(",") +
      "}"
    );
  } finally {
    ancestors.delete(value);
  }
}

export function tradeCanonicalBytes(value: unknown): Uint8Array {
  if (value === null || typeof value !== "object" || Array.isArray(value)) {
    throw new Error("trade JSON root must be an object");
  }
  const encoded = utf8(canonicalString(value, "$", 0, { nodes: 0 }, new Set()));
  if (encoded.byteLength > MAX_BYTES) throw new Error("trade JSON exceeds byte limit");
  return encoded;
}

function asObject(value: unknown, label: string): Record<string, unknown> {
  if (value === null || typeof value !== "object" || Array.isArray(value)) {
    throw new Error(`${label} must be an object`);
  }
  return value as Record<string, unknown>;
}

function exactObject(
  value: unknown,
  expected: readonly string[],
  label: string
): Record<string, unknown> {
  const object = asObject(value, label);
  const actual = Object.keys(object).sort();
  const wanted = [...expected].sort();
  if (
    actual.length !== wanted.length ||
    actual.some((key, index) => key !== wanted[index])
  ) {
    throw new Error(`${label} fields invalid`);
  }
  return object;
}

function boundedString(
  value: unknown,
  label: string,
  minimum: number,
  maximum: number
): string {
  if (
    typeof value !== "string" ||
    [...value].length < minimum ||
    [...value].length > maximum ||
    hasLoneSurrogate(value)
  ) {
    throw new Error(`${label} is invalid`);
  }
  return value;
}

const TOKEN = /^[a-z0-9][a-z0-9._:/-]*$/;
const OFFER_ID =
  /^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)+(?:\/[a-z0-9](?:[a-z0-9._-]{0,126}[a-z0-9])?)?$/;
const RULE_ID =
  /^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)+(?:\/[a-z0-9](?:[a-z0-9._-]{0,30}[a-z0-9])?)?$/;
const DIGEST = /^sha256:[0-9a-f]{64}$/;
const RESOURCE_ID =
  /^([a-z][a-z0-9+.-]{0,31}):[A-Za-z0-9._~!$&'()*+,;=:@%/?#\[\]-]+$/;
const QUANTITY = /^(?:[1-9][0-9]*(?:\.[0-9]*[1-9])?|0\.[0-9]*[1-9])$/;
const EXTENSION_ID =
  /^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)+\/[a-z0-9](?:[a-z0-9._-]{0,30}[a-z0-9])?$/;
const TIMESTAMP =
  /^([0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2})(?:\.([0-9]{1,9}))?Z$/;
const RECOGNITION_AUDIT_TIMESTAMP =
  /^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}(?:\.[0-9]{6})?Z$/;
const RECOGNITION_ID = /^nth-trade-recognition-sha256:[0-9a-f]{64}$/;
const RECOGNITION_AUDIT_FIELDS = [
  "protocol_version",
  "recognition_id",
  "recognition_digest",
  "rule_id",
  "package_digest",
  "issuer_did",
  "sequence",
  "decision",
  "issued_at",
  "not_after",
] as const;
const UNSAFE_RESOURCE_SCHEMES = new Set(["data", "file", "javascript", "vbscript"]);

const OFFER_FIELDS = [
  "kind",
  "protocol_version",
  "offer_id",
  "revision",
  "previous_offer_digest",
  "state",
  "publisher_did",
  "title",
  "summary",
  "provides",
  "requests",
  "rule_refs",
  "published_at",
  "not_after",
  "extensions",
  "proof",
] as const;
const LEG_FIELDS = [
  "leg_id",
  "resource_type",
  "resource_id",
  "quantity",
  "unit",
  "descriptor_digest",
] as const;
const RULE_REF_FIELDS = ["rule_id", "digest"] as const;
const PROOF_FIELDS = [
  "type",
  "created",
  "verification_method",
  "proof_purpose",
  "proof_value",
] as const;

const DISPUTE_STATEMENT_FIELDS = [
  "kind",
  "protocol_version",
  "statement_id",
  "dispute_id",
  "order_digest",
  "receipt_digest",
  "review_digest",
  "review_id",
  "author_did",
  "author_role",
  "statement_type",
  "parent_statement_digests",
  "reason_codes",
  "claim",
  "evidence",
  "rule_action",
  "created_at",
  "proof",
] as const;
const DISPUTE_CLAIM_FIELDS = [
  "claim_type",
  "media_type",
  "digest",
  "size",
  "schema_digest",
] as const;
const DISPUTE_EVIDENCE_FIELDS = [
  "purpose",
  "media_type",
  "digest",
  "size",
] as const;
const DISPUTE_RULE_ACTION_FIELDS = [
  "rule_id",
  "digest",
  "hook",
  "hook_version",
] as const;
const DISPUTE_PACKAGE_FIELDS = ["digest", "manifest", "resources"] as const;
const DISPUTE_PACKAGE_RESOURCE_FIELDS = ["bytes_hex", "digest"] as const;
const DISPUTE_TIMESTAMP =
  /^([0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2})(?:\.([0-9]{6}))?Z$/;
const DISPUTE_STATEMENT_ID =
  /^nth-trade-dispute-statement-sha256:[0-9a-f]{64}$/;
const DISPUTE_ID = /^nth-trade-dispute-sha256:[0-9a-f]{64}$/;
const DISPUTE_REVIEW_ID = /^nth-trade-review-sha256:[0-9a-f]{64}$/;
const DISPUTE_DELIVERY_ID =
  /^nth:trade:dispute-statement-delivery:sha256:[0-9a-f]{64}$/;
const DISPUTE_NONCE = /^(?:[0-9a-f]{2}){16,64}$/;
const EVENT_ID = /^[0-9a-f]{64}$/;
const MAX_DISPUTE_ACK_BYTES = 4_096;
const DISPUTE_DELIVERY_FIELDS = [
  "kind", "protocol_version", "delivery_id", "nonce", "order_digest",
  "receipt_digest", "review_digest", "statement_digest", "sender_did",
  "recipient_did", "created_at", "not_after", "statement", "proof",
] as const;
const DISPUTE_ACK_FIELDS = [
  "kind", "protocol_version", "delivery_id", "delivery_digest", "order_digest",
  "receipt_digest", "review_digest", "statement_digest", "sender_did",
  "receiver_did", "received_at", "audit_event_id", "status", "proof",
] as const;
const ORDER_FIELDS = [
  "kind", "protocol_version", "order_id", "proposal_digest",
  "acceptance_digest", "offer_digest", "maker_did", "taker_did",
  "rule_bindings", "policy_digests", "created_at", "snapshot",
] as const;
const ORDER_SNAPSHOT_FIELDS = ["offer", "proposal", "acceptance"] as const;
const ORDER_POLICY_DIGEST_FIELDS = ["maker", "taker"] as const;
const PROPOSAL_FIELDS = [
  "kind", "protocol_version", "offer_publisher_did", "offer_id",
  "offer_revision", "offer_digest", "canonical_chain_digests",
  "maker_did", "taker_did", "rule_bindings", "taker_policy_digest",
  "taker_policy", "terms", "created_at", "not_after", "proof",
] as const;
const ACCEPTANCE_FIELDS = [
  "kind", "protocol_version", "proposal_digest", "offer_digest",
  "maker_did", "taker_did", "rule_bindings", "maker_policy_digest",
  "maker_policy", "created_at", "proof",
] as const;
const RULE_BINDING_FIELDS = ["rule_id", "digest"] as const;
const RULE_POLICY_FIELDS = [
  "kind", "protocol_version", "accepted_publishers",
  "accepted_package_digests", "available_capabilities",
  "allowed_permissions", "allowed_execution_modes",
  "approved_executable_digests", "max_depth", "max_packages",
  "max_resource_bytes",
] as const;
const EXECUTION_RECEIPT_FIELDS = [
  "kind", "protocol_version", "execution_id", "order_id", "order_digest",
  "executor_did", "executor_role", "readiness", "readiness_digest",
  "adapter", "operation", "outcome", "result", "evidence", "started_at",
  "completed_at", "proof",
] as const;
const EXECUTION_READINESS_FIELDS = [
  "kind", "protocol_version", "order_digest", "executor_policy_digest",
  "ordered_package_digests", "required_capabilities", "required_permissions",
  "execution_modes", "resolved_resource_bytes", "evaluated_at",
] as const;
const EXECUTION_ADAPTER_FIELDS = [
  "adapter_id", "adapter_version", "adapter_digest", "execution_mode",
] as const;
const EXECUTION_OPERATION_FIELDS = [
  "operation_id", "rule_id", "package_digest", "hook_name", "hook_version",
  "executor_role", "input", "input_schema_digest", "output_schema_digest",
  "side_effect",
] as const;
const EXECUTION_CONTENT_FIELDS = ["media_type", "digest", "size_bytes"] as const;
const EXECUTION_EVIDENCE_FIELDS = [
  "evidence_type", "media_type", "digest", "size_bytes",
] as const;
const EXECUTION_TERMS_FIELDS = ["grants"] as const;
const EXECUTION_GRANT_FIELDS = [
  "operation_id", "rule_id", "package_digest", "hook_name", "hook_version",
  "executor_role",
] as const;
const RECEIPT_REVIEW_FIELDS = [
  "kind", "protocol_version", "review_id", "order_id", "order_digest",
  "execution_id", "receipt_digest", "reviewer_did", "reviewer_role",
  "verifier_policy_digest", "adapter_policy_digest", "decision",
  "reason_codes", "reviewed_at", "proof",
] as const;
const TRANSPORT_PROOF_FIELDS = [
  "type", "created", "verification_method", "proof_purpose", "proof_value",
] as const;
const DISPUTE_REASON = /^[a-z][a-z0-9._:-]{0,127}$/;
const DISPUTE_TOKEN = /^[a-z][a-z0-9._:/-]{0,127}$/;
const DISPUTE_HOOK = /^[a-z0-9][a-z0-9._:/-]{0,127}$/;
const DISPUTE_HOOK_VERSION = /^[a-z0-9][a-z0-9._:/-]{0,31}$/;
const DISPUTE_MEDIA_TYPE = /^[a-z0-9!#$&^_.+-]+\/[a-z0-9!#$&^_.+-]+$/;
const ORDER_ID = /^nth-trade-order-sha256:[0-9a-f]{64}$/;
const EXECUTION_ID = /^nth-trade-execution-sha256:[0-9a-f]{64}$/;
const REVIEW_ID = /^nth-trade-review-sha256:[0-9a-f]{64}$/;
const OPERATION_ID = /^[a-z][a-z0-9._:-]{0,127}$/;
const ADAPTER_ID = OFFER_ID;
const SEMVER = /^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)(?:-[0-9A-Za-z.-]+)?(?:\+[0-9A-Za-z.-]+)?$/;
const ASCII_TOKEN = /^[a-z0-9][a-z0-9._:/-]{0,159}$/;
const REVIEW_REASON = /^[a-z][a-z0-9._:-]{0,127}$/;
const EXECUTION_MODES = new Set([
  "declarative", "adapter", "sandboxed_wasm", "external_service",
]);
const EXECUTOR_ROLES = new Set(["maker", "taker"]);
const EXECUTION_OUTCOMES = new Set(["succeeded", "failed", "cancelled"]);
const SIDE_EFFECTS = new Set(["none", "local", "external"]);
const MAX_DISPUTE_CONTENT_BYTES = 16 * 1024 * 1024;
const MAX_DISPUTE_TOTAL_EVIDENCE_BYTES = 64 * 1024 * 1024;

function token(value: unknown, label: string, maximum: number): string {
  const text = boundedString(value, label, 1, maximum);
  if (!TOKEN.test(text)) throw new Error(`${label} is not a namespaced token`);
  return text;
}

function digest(value: unknown, label: string): string {
  const text = boundedString(value, label, 71, 71);
  if (!DIGEST.test(text)) throw new Error(`${label} is not a sha256 digest`);
  return text;
}

function timestampNanos(value: unknown, label: string): bigint {
  const text = boundedString(value, label, 1, 35);
  const match = TIMESTAMP.exec(text);
  if (!match) throw new Error(`${label} is not a UTC RFC3339 timestamp`);
  const base = match[1] ?? "";
  if (Number(base.slice(0, 4)) < 1) {
    throw new Error(`${label} is not a real timestamp`);
  }
  const date = new Date(`${base}Z`);
  if (
    Number.isNaN(date.getTime()) ||
    date.toISOString().slice(0, 19) !== base
  ) {
    throw new Error(`${label} is not a real timestamp`);
  }
  const nanos = BigInt((match[2] ?? "").padEnd(9, "0") || "0");
  return BigInt(date.getTime()) * 1_000_000n + nanos;
}

function asArray(value: unknown, label: string): unknown[] {
  if (!Array.isArray(value)) throw new Error(`${label} must be an array`);
  return value;
}

function validateLegs(value: unknown, label: string, minimum: number): Set<string> {
  const legs = asArray(value, label);
  if (legs.length < minimum || legs.length > 32) {
    throw new Error(`${label} must contain ${minimum}..32 entries`);
  }
  const ids: string[] = [];
  for (const [index, raw] of legs.entries()) {
    const leg = exactObject(raw, LEG_FIELDS, `${label}[${index}]`);
    const legId = token(leg.leg_id, `${label}[${index}].leg_id`, 64);
    token(leg.resource_type, `${label}[${index}].resource_type`, 160);
    const resourceId = boundedString(
      leg.resource_id,
      `${label}[${index}].resource_id`,
      1,
      512
    );
    const resourceMatch = RESOURCE_ID.exec(resourceId);
    if (!resourceMatch || UNSAFE_RESOURCE_SCHEMES.has(resourceMatch[1] ?? "")) {
      throw new Error(`${label}[${index}].resource_id is invalid`);
    }
    const quantity = boundedString(
      leg.quantity,
      `${label}[${index}].quantity`,
      1,
      80
    );
    if (
      !QUANTITY.test(quantity) ||
      quantity.replace(".", "").length > 78 ||
      (quantity.includes(".") && (quantity.split(".")[1]?.length ?? 0) > 30)
    ) {
      throw new Error(`${label}[${index}].quantity is invalid`);
    }
    token(leg.unit, `${label}[${index}].unit`, 80);
    digest(leg.descriptor_digest, `${label}[${index}].descriptor_digest`);
    ids.push(legId);
  }
  if (new Set(ids).size !== ids.length) {
    throw new Error(`${label} contains duplicate leg_id values`);
  }
  if (ids.some((value, index) => value !== [...ids].sort()[index])) {
    throw new Error(`${label} must be sorted by leg_id`);
  }
  return new Set(ids);
}

function validateRuleRefs(value: unknown): void {
  const refs = asArray(value, "rule_refs");
  if (refs.length > 32) throw new Error("rule_refs exceeds 32 entries");
  const order: string[] = [];
  for (const [index, raw] of refs.entries()) {
    const ref = exactObject(raw, RULE_REF_FIELDS, `rule_refs[${index}]`);
    const ruleId = boundedString(ref.rule_id, `rule_refs[${index}].rule_id`, 3, 160);
    if (!RULE_ID.test(ruleId)) throw new Error(`rule_refs[${index}].rule_id is invalid`);
    order.push(`${ruleId}\0${digest(ref.digest, `rule_refs[${index}].digest`)}`);
  }
  if (new Set(order).size !== order.length) {
    throw new Error("rule_refs contains duplicate entries");
  }
  if (order.some((value, index) => value !== [...order].sort()[index])) {
    throw new Error("rule_refs must be sorted");
  }
}

function validateOfferSnapshot(document: Record<string, unknown>): void {
  exactObject(document, OFFER_FIELDS, "offer");
  if (
    document.kind !== "org.nthdao.trade.offer" ||
    document.protocol_version !== "2.0"
  ) {
    throw new Error("unsupported offer protocol");
  }
  const offerId = boundedString(document.offer_id, "offer_id", 3, 256);
  if (!OFFER_ID.test(offerId)) throw new Error("offer_id is invalid");
  const revision = document.revision;
  if (
    typeof revision !== "number" ||
    !Number.isInteger(revision) ||
    revision < 1 ||
    revision > 2_147_483_647
  ) {
    throw new Error("revision is invalid");
  }
  if (revision === 1) {
    if (document.previous_offer_digest !== null) {
      throw new Error("revision 1 cannot bind a previous offer");
    }
  } else {
    digest(document.previous_offer_digest, "previous_offer_digest");
  }
  if (document.state !== "active" && document.state !== "withdrawn") {
    throw new Error("state is invalid");
  }
  if (revision === 1 && document.state === "withdrawn") {
    throw new Error("an initial offer cannot be withdrawn");
  }
  boundedString(document.publisher_did, "publisher_did", 1, 256);
  boundedString(document.title, "title", 1, 160);
  const summary = boundedString(document.summary, "summary", 0, 2_000);
  if (utf8(summary).byteLength > 8_000) throw new Error("summary is too large");
  const provides = validateLegs(document.provides, "provides", 1);
  const requests = validateLegs(document.requests, "requests", 0);
  if ([...provides].some((legId) => requests.has(legId))) {
    throw new Error("leg_id values overlap");
  }
  validateRuleRefs(document.rule_refs);
  const published = timestampNanos(document.published_at, "published_at");
  if (
    document.not_after !== null &&
    timestampNanos(document.not_after, "not_after") <= published
  ) {
    throw new Error("not_after must be later than published_at");
  }
  const extensions = asObject(document.extensions, "extensions");
  if (Object.keys(extensions).length > 32) throw new Error("extensions exceeds 32 entries");
  for (const [key, value] of Object.entries(extensions)) {
    if (!EXTENSION_ID.test(key)) throw new Error(`extension id ${key} is invalid`);
    asObject(value, `extension ${key}`);
  }

  const proof = exactObject(document.proof, PROOF_FIELDS, "proof");
  if (
    proof.type !== "NthEd25519SignatureV1" ||
    proof.proof_purpose !== "assertionMethod"
  ) {
    throw new Error("proof options are invalid");
  }
  const proofCreated = timestampNanos(proof.created, "proof.created");
  if (proofCreated < published) throw new Error("proof predates publication");
  if (
    document.not_after !== null &&
    timestampNanos(document.not_after, "not_after") <= proofCreated
  ) {
    throw new Error("offer expires before its proof");
  }
  if (
    typeof document.publisher_did !== "string" ||
    proof.verification_method !==
      `${document.publisher_did}#${document.publisher_did.slice("did:key:".length)}`
  ) {
    throw new Error("verification_method does not match publisher_did");
  }
  decodeDidKey(document.publisher_did);
  decodeBase64Url(boundedString(proof.proof_value, "proof.proof_value", 86, 86));
}

export function validateTradeOffer(offer: unknown): Record<string, unknown> {
  const snapshot = asObject(
    JSON.parse(new TextDecoder().decode(tradeCanonicalBytes(offer))),
    "offer"
  );
  validateOfferSnapshot(snapshot);
  return deepFreezeJson(snapshot);
}

function deepFreezeJson<T>(value: T): T {
  if (value !== null && typeof value === "object") {
    for (const child of Object.values(value as Record<string, unknown>)) {
      deepFreezeJson(child);
    }
    Object.freeze(value);
  }
  return value;
}

function concatBytes(...parts: Uint8Array[]): Uint8Array {
  const length = parts.reduce((total, part) => total + part.byteLength, 0);
  const output = new Uint8Array(length);
  let offset = 0;
  for (const part of parts) {
    output.set(part, offset);
    offset += part.byteLength;
  }
  return output;
}

function asArrayBuffer(value: Uint8Array): ArrayBuffer {
  const copy = new Uint8Array(value.byteLength);
  copy.set(value);
  return copy.buffer;
}

export function manifestSigningInput(
  manifest: unknown,
  domain = TRADE_RULE_MANIFEST_DOMAIN
): Uint8Array {
  const document = asObject(manifest, "manifest");
  const proof = asObject(document.proof, "proof");
  if (typeof proof.proof_value !== "string") {
    throw new Error("proof.proof_value must be a string");
  }
  const signingProof = { ...proof };
  delete signingProof.proof_value;
  const signingBody = { ...document, proof: signingProof };
  return concatBytes(utf8(domain), new Uint8Array([0]), tradeCanonicalBytes(signingBody));
}

export function offerSigningInput(
  offer: unknown,
  domain = TRADE_OFFER_DOMAIN
): Uint8Array {
  return manifestSigningInput(offer, domain);
}

export function recognitionSigningInput(
  recognition: unknown,
  domain = TRADE_RULE_RECOGNITION_DOMAIN
): Uint8Array {
  return manifestSigningInput(recognition, domain);
}

export function disputeStatementSigningInput(
  statement: unknown,
  domain = TRADE_DISPUTE_STATEMENT_DOMAIN
): Uint8Array {
  return manifestSigningInput(statement, domain);
}

export function disputeStatementDeliverySigningInput(
  delivery: unknown,
  domain = TRADE_DISPUTE_STATEMENT_DELIVERY_DOMAIN
): Uint8Array {
  return manifestSigningInput(delivery, domain);
}

export function disputeStatementAcknowledgementSigningInput(
  acknowledgement: unknown,
  domain = TRADE_DISPUTE_STATEMENT_ACKNOWLEDGEMENT_DOMAIN
): Uint8Array {
  return manifestSigningInput(acknowledgement, domain);
}

export function validateRuleRecognitionAuditPayload(
  value: unknown
): Record<string, unknown> {
  const payload = exactObject(
    value,
    RECOGNITION_AUDIT_FIELDS,
    "Recognition Spine payload"
  );
  if (payload.protocol_version !== "1") {
    throw new Error("Recognition Spine payload protocol version is unsupported");
  }
  if (
    typeof payload.recognition_id !== "string" ||
    !RECOGNITION_ID.test(payload.recognition_id)
  ) {
    throw new Error("Recognition Spine payload recognition_id is invalid");
  }
  digest(payload.recognition_digest, "recognition_digest");
  digest(payload.package_digest, "package_digest");
  if (typeof payload.rule_id !== "string" || !RULE_ID.test(payload.rule_id)) {
    throw new Error("Recognition Spine payload rule_id is invalid");
  }
  if (typeof payload.issuer_did !== "string") {
    throw new Error("Recognition Spine payload issuer_did is invalid");
  }
  decodeDidKey(payload.issuer_did);
  if (
    typeof payload.sequence !== "number" ||
    !Number.isSafeInteger(payload.sequence) ||
    payload.sequence < 1 ||
    payload.sequence > 2_147_483_647
  ) {
    throw new Error("Recognition Spine payload sequence is invalid");
  }
  if (
    payload.decision !== "recognized" &&
    payload.decision !== "deprecated" &&
    payload.decision !== "revoked"
  ) {
    throw new Error("Recognition Spine payload decision is invalid");
  }
  for (const field of ["issued_at", "not_after"] as const) {
    if (
      typeof payload[field] !== "string" ||
      !RECOGNITION_AUDIT_TIMESTAMP.test(payload[field]) ||
      payload[field].endsWith(".000000Z")
    ) {
      throw new Error(`Recognition Spine payload ${field} is invalid`);
    }
  }
  const issuedAt = timestampNanos(payload.issued_at, "issued_at");
  const notAfter = timestampNanos(payload.not_after, "not_after");
  if (notAfter <= issuedAt) {
    throw new Error(
      "Recognition Spine payload not_after must follow issued_at"
    );
  }
  return payload;
}

function decodeBase58(value: string): Uint8Array {
  const alphabet = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
  let number = 0n;
  for (const character of value) {
    const index = alphabet.indexOf(character);
    if (index < 0) throw new Error("invalid base58btc");
    number = number * 58n + BigInt(index);
  }
  const body: number[] = [];
  while (number > 0n) {
    body.push(Number(number % 256n));
    number /= 256n;
  }
  body.reverse();
  let leadingZeros = 0;
  while (value[leadingZeros] === "1") leadingZeros += 1;
  return new Uint8Array([...new Array(leadingZeros).fill(0), ...body]);
}

function decodeDidKey(value: string): Uint8Array {
  const prefix = "did:key:z";
  if (!value.startsWith(prefix)) throw new Error("unsupported DID");
  const decoded = decodeBase58(value.slice(prefix.length));
  if (decoded.length !== 34 || decoded[0] !== 0xed || decoded[1] !== 0x01) {
    throw new Error("DID is not an Ed25519 did:key");
  }
  return decoded.slice(2);
}

function decodeBase64Url(value: string): Uint8Array {
  if (!/^[A-Za-z0-9_-]{86}$/.test(value)) throw new Error("invalid signature encoding");
  const base64 = value.replace(/-/g, "+").replace(/_/g, "/") + "==";
  const binary = atob(base64);
  const decoded = Uint8Array.from(binary, (character) => character.charCodeAt(0));
  if (decoded.byteLength !== 64) throw new Error("invalid Ed25519 signature length");
  const canonical = btoa(String.fromCharCode(...decoded))
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=+$/g, "");
  if (canonical !== value) throw new Error("non-canonical signature encoding");
  return decoded;
}

export async function verifyManifestSignature(
  manifest: unknown,
  subtle: SubtleCrypto = globalThis.crypto.subtle,
  domain = TRADE_RULE_MANIFEST_DOMAIN
): Promise<boolean> {
  try {
    const document = asObject(
      JSON.parse(new TextDecoder().decode(tradeCanonicalBytes(manifest))),
      "manifest"
    );
    const proof = asObject(document.proof, "proof");
    if (
      document.kind !== "org.nthdao.trade.rule-manifest" ||
      document.protocol_version !== "1.0" ||
      proof.type !== "NthEd25519SignatureV1" ||
      proof.proof_purpose !== "assertionMethod" ||
      typeof document.publisher_did !== "string" ||
      typeof proof.verification_method !== "string" ||
      proof.verification_method !==
        `${document.publisher_did}#${document.publisher_did.slice("did:key:".length)}` ||
      typeof proof.proof_value !== "string"
    ) {
      return false;
    }
    const keyBytes = decodeDidKey(document.publisher_did);
    const signature = decodeBase64Url(proof.proof_value);
    const key = await subtle.importKey(
      "raw",
      asArrayBuffer(keyBytes),
      { name: "Ed25519" },
      false,
      ["verify"]
    );
    return await subtle.verify(
      { name: "Ed25519" },
      key,
      asArrayBuffer(signature),
      asArrayBuffer(manifestSigningInput(document, domain))
    );
  } catch {
    return false;
  }
}

export async function verifyOfferSourceSignature(
  offer: unknown,
  subtle: SubtleCrypto = globalThis.crypto.subtle,
  domain = TRADE_OFFER_DOMAIN
): Promise<boolean> {
  try {
    const document = asObject(
      JSON.parse(new TextDecoder().decode(tradeCanonicalBytes(offer))),
      "offer"
    );
    const proof = asObject(document.proof, "proof");
    if (
      document.kind !== "org.nthdao.trade.offer" ||
      document.protocol_version !== "2.0" ||
      proof.type !== "NthEd25519SignatureV1" ||
      proof.proof_purpose !== "assertionMethod" ||
      typeof document.publisher_did !== "string" ||
      typeof proof.verification_method !== "string" ||
      proof.verification_method !==
        `${document.publisher_did}#${document.publisher_did.slice("did:key:".length)}` ||
      typeof proof.proof_value !== "string"
    ) {
      return false;
    }
    const keyBytes = decodeDidKey(document.publisher_did);
    const signature = decodeBase64Url(proof.proof_value);
    const key = await subtle.importKey(
      "raw",
      asArrayBuffer(keyBytes),
      { name: "Ed25519" },
      false,
      ["verify"]
    );
    return await subtle.verify(
      { name: "Ed25519" },
      key,
      asArrayBuffer(signature),
      asArrayBuffer(offerSigningInput(document, domain))
    );
  } catch {
    return false;
  }
}

export async function verifyRuleRecognitionSignature(
  recognition: unknown,
  subtle: SubtleCrypto = globalThis.crypto.subtle,
  domain = TRADE_RULE_RECOGNITION_DOMAIN
): Promise<boolean> {
  try {
    const document = asObject(
      JSON.parse(new TextDecoder().decode(tradeCanonicalBytes(recognition))),
      "recognition"
    );
    const proof = asObject(document.proof, "proof");
    if (
      document.kind !== "nth.dao.trade.rule-recognition" ||
      document.protocol_version !== "1" ||
      proof.type !== "NthEd25519SignatureV1" ||
      proof.proof_purpose !== "tradeRuleRecognition" ||
      typeof document.issuer_did !== "string" ||
      typeof proof.verification_method !== "string" ||
      proof.verification_method !==
        `${document.issuer_did}#${document.issuer_did.slice("did:key:".length)}` ||
      typeof proof.proof_value !== "string"
    ) {
      return false;
    }
    const keyBytes = decodeDidKey(document.issuer_did);
    const signature = decodeBase64Url(proof.proof_value);
    const key = await subtle.importKey(
      "raw",
      asArrayBuffer(keyBytes),
      { name: "Ed25519" },
      false,
      ["verify"]
    );
    return await subtle.verify(
      { name: "Ed25519" },
      key,
      asArrayBuffer(signature),
      asArrayBuffer(recognitionSigningInput(document, domain))
    );
  } catch {
    return false;
  }
}

export async function verifyTradeDisputeStatementSignature(
  statement: unknown,
  subtle: SubtleCrypto = globalThis.crypto.subtle,
  domain = TRADE_DISPUTE_STATEMENT_DOMAIN
): Promise<boolean> {
  try {
    const document = asObject(
      JSON.parse(new TextDecoder().decode(tradeCanonicalBytes(statement))),
      "trade dispute statement"
    );
    const proof = asObject(document.proof, "proof");
    if (
      document.kind !== "nth.dao.trade.dispute-statement" ||
      document.protocol_version !== "1" ||
      proof.type !== "Ed25519Signature2020" ||
      proof.proof_purpose !== "tradeDisputeStatement" ||
      proof.created !== document.created_at ||
      typeof document.author_did !== "string" ||
      typeof proof.verification_method !== "string" ||
      proof.verification_method !==
        `${document.author_did}#${document.author_did.slice("did:key:".length)}` ||
      typeof proof.proof_value !== "string"
    ) {
      return false;
    }
    const keyBytes = decodeDidKey(document.author_did);
    const signature = decodeBase64Url(proof.proof_value);
    const key = await subtle.importKey(
      "raw",
      asArrayBuffer(keyBytes),
      { name: "Ed25519" },
      false,
      ["verify"]
    );
    return await subtle.verify(
      { name: "Ed25519" },
      key,
      asArrayBuffer(signature),
      asArrayBuffer(disputeStatementSigningInput(document, domain))
    );
  } catch {
    return false;
  }
}

const verifiedTradeDisputeArtifactBundles = new WeakSet<object>();

export type VerifiedTradeDisputeArtifacts = Readonly<{
  order: unknown;
  receipt: unknown;
  review: unknown;
}>;

function frozenCanonicalTradeObject(value: unknown): unknown {
  const clone = JSON.parse(new TextDecoder().decode(tradeCanonicalBytes(value)));
  const freeze = (item: unknown): unknown => {
    if (item !== null && typeof item === "object") {
      for (const child of Object.values(item as Record<string, unknown>)) {
        freeze(child);
      }
      Object.freeze(item);
    }
    return item;
  };
  return freeze(clone);
}

function canonicalEqual(left: unknown, right: unknown): boolean {
  return (
    canonicalString(left, "$left", 0, { nodes: 0 }, new Set()) ===
    canonicalString(right, "$right", 0, { nodes: 0 }, new Set())
  );
}

function validateSortedUniqueStrings(
  value: unknown,
  label: string,
  maximum: number,
  validator: (item: string) => boolean
): string[] {
  const values = asArray(value, label);
  if (
    values.length > maximum ||
    values.some((item) => typeof item !== "string" || !validator(item))
  ) {
    throw new Error(`${label} is invalid`);
  }
  const strings = values as string[];
  if (
    new Set(strings).size !== strings.length ||
    strings.some((item, index) => item !== [...strings].sort()[index])
  ) {
    throw new Error(`${label} must be sorted and unique`);
  }
  return strings;
}

async function verifyArtifactSignature(
  document: Record<string, unknown>,
  signerDid: string,
  purpose: string,
  createdAt: string,
  domain: string,
  subtle: SubtleCrypto
): Promise<void> {
  decodeDidKey(signerDid);
  const proof = exactObject(document.proof, PROOF_FIELDS, "proof");
  if (
    proof.type !== "Ed25519Signature2020" ||
    proof.created !== createdAt ||
    proof.verification_method !==
      `${signerDid}#${signerDid.slice("did:key:".length)}` ||
    proof.proof_purpose !== purpose ||
    typeof proof.proof_value !== "string"
  ) {
    throw new Error("artifact proof binding is invalid");
  }
  timestampNanos(proof.created, "proof.created");
  const key = await subtle.importKey(
    "raw",
    asArrayBuffer(decodeDidKey(signerDid)),
    { name: "Ed25519" },
    false,
    ["verify"]
  );
  const valid = await subtle.verify(
    { name: "Ed25519" },
    key,
    asArrayBuffer(decodeBase64Url(proof.proof_value)),
    asArrayBuffer(manifestSigningInput(document, domain))
  );
  if (!valid) throw new Error("artifact signature is invalid");
}

async function validateRulePolicy(
  value: unknown,
  expectedDigest: unknown,
  label: string,
  subtle: SubtleCrypto
): Promise<Record<string, unknown>> {
  const policy = exactObject(value, RULE_POLICY_FIELDS, label);
  if (
    policy.kind !== "nth.dao.trade.rule-resolution-policy" ||
    policy.protocol_version !== "1"
  ) {
    throw new Error(`${label} version is invalid`);
  }
  validateSortedUniqueStrings(policy.accepted_publishers, `${label}.accepted_publishers`, 4096, (item) => {
    try { decodeDidKey(item); return true; } catch { return false; }
  });
  for (const field of ["accepted_package_digests", "approved_executable_digests"] as const) {
    validateSortedUniqueStrings(policy[field], `${label}.${field}`, 4096, (item) => DIGEST.test(item));
  }
  for (const field of ["available_capabilities", "allowed_permissions"] as const) {
    validateSortedUniqueStrings(policy[field], `${label}.${field}`, 1024, (item) => ASCII_TOKEN.test(item));
  }
  const modes = validateSortedUniqueStrings(
    policy.allowed_execution_modes,
    `${label}.allowed_execution_modes`,
    EXECUTION_MODES.size,
    (item) => EXECUTION_MODES.has(item)
  );
  if (!modes.includes("declarative")) {
    throw new Error(`${label}.allowed_execution_modes must include declarative`);
  }
  for (const [field, maximum] of [
    ["max_depth", 128], ["max_packages", 4096],
    ["max_resource_bytes", 1024 * 1024 * 1024],
  ] as const) {
    const item = policy[field];
    if (!Number.isSafeInteger(item) || (item as number) < 1 || (item as number) > maximum) {
      throw new Error(`${label}.${field} is invalid`);
    }
  }
  if (digest(expectedDigest, `${label}_digest`) !== await sha256Digest(policy, subtle)) {
    throw new Error(`${label}_digest does not match ${label}`);
  }
  return policy;
}

function validateRuleBindings(value: unknown): Record<string, unknown>[] {
  const values = asArray(value, "rule_bindings");
  if (values.length > 256) throw new Error("rule_bindings exceeds 256 entries");
  const output = values.map((raw, index) => {
    const item = exactObject(raw, RULE_BINDING_FIELDS, `rule_bindings[${index}]`);
    if (typeof item.rule_id !== "string" || !RULE_ID.test(item.rule_id)) {
      throw new Error(`rule_bindings[${index}].rule_id is invalid`);
    }
    digest(item.digest, `rule_bindings[${index}].digest`);
    return item;
  });
  const identities = output.map((item) => `${item.rule_id}\0${item.digest}`);
  const ruleIds = output.map((item) => item.rule_id as string);
  const digests = output.map((item) => item.digest as string);
  if (
    new Set(identities).size !== output.length ||
    new Set(ruleIds).size !== output.length ||
    new Set(digests).size !== output.length ||
    identities.some((item, index) => item !== [...identities].sort()[index])
  ) {
    throw new Error("rule_bindings must be sorted and one-to-one");
  }
  return output;
}

async function verifyProposalArtifact(
  value: unknown,
  subtle: SubtleCrypto
): Promise<Record<string, unknown>> {
  const proposal = exactObject(value, PROPOSAL_FIELDS, "proposal");
  if (proposal.kind !== "nth.dao.trade.proposal" || proposal.protocol_version !== "1") {
    throw new Error("proposal version is invalid");
  }
  const publisher = boundedString(proposal.offer_publisher_did, "offer_publisher_did", 1, 256);
  const maker = boundedString(proposal.maker_did, "maker_did", 1, 256);
  const taker = boundedString(proposal.taker_did, "taker_did", 1, 256);
  decodeDidKey(publisher); decodeDidKey(maker); decodeDidKey(taker);
  if (publisher !== maker || maker === taker) throw new Error("proposal party binding is invalid");
  if (typeof proposal.offer_id !== "string" || !OFFER_ID.test(proposal.offer_id)) {
    throw new Error("proposal offer_id is invalid");
  }
  const revision = proposal.offer_revision;
  if (!Number.isSafeInteger(revision) || (revision as number) < 1 || (revision as number) > 1_000_000) {
    throw new Error("proposal offer_revision is invalid");
  }
  const offerDigest = digest(proposal.offer_digest, "proposal.offer_digest");
  const chain = asArray(proposal.canonical_chain_digests, "canonical_chain_digests");
  if (
    chain.length !== revision ||
    chain.some((item) => typeof item !== "string" || !DIGEST.test(item)) ||
    new Set(chain).size !== chain.length ||
    chain[chain.length - 1] !== offerDigest
  ) {
    throw new Error("canonical_chain_digests is invalid");
  }
  validateRuleBindings(proposal.rule_bindings);
  await validateRulePolicy(proposal.taker_policy, proposal.taker_policy_digest, "taker_policy", subtle);
  const terms = asObject(proposal.terms, "terms");
  if (tradeCanonicalBytes(terms).byteLength > 64 * 1024) throw new Error("terms exceeds byte limit");
  const created = timestampNanos(proposal.created_at, "proposal.created_at");
  if (timestampNanos(proposal.not_after, "proposal.not_after") <= created) {
    throw new Error("proposal not_after must follow created_at");
  }
  await verifyArtifactSignature(
    proposal, taker, "tradeProposal",
    boundedString(proposal.created_at, "proposal.created_at", 1, 35),
    TRADE_PROPOSAL_DOMAIN, subtle
  );
  return proposal;
}

async function verifyAcceptanceArtifact(
  value: unknown,
  subtle: SubtleCrypto
): Promise<Record<string, unknown>> {
  const acceptance = exactObject(value, ACCEPTANCE_FIELDS, "acceptance");
  if (acceptance.kind !== "nth.dao.trade.acceptance" || acceptance.protocol_version !== "1") {
    throw new Error("acceptance version is invalid");
  }
  const maker = boundedString(acceptance.maker_did, "acceptance.maker_did", 1, 256);
  const taker = boundedString(acceptance.taker_did, "acceptance.taker_did", 1, 256);
  decodeDidKey(maker); decodeDidKey(taker);
  if (maker === taker) throw new Error("acceptance parties must differ");
  digest(acceptance.proposal_digest, "acceptance.proposal_digest");
  digest(acceptance.offer_digest, "acceptance.offer_digest");
  validateRuleBindings(acceptance.rule_bindings);
  await validateRulePolicy(acceptance.maker_policy, acceptance.maker_policy_digest, "maker_policy", subtle);
  await verifyArtifactSignature(
    acceptance, maker, "tradeAcceptance",
    boundedString(acceptance.created_at, "acceptance.created_at", 1, 35),
    TRADE_ACCEPTANCE_DOMAIN, subtle
  );
  return acceptance;
}

async function verifyOrderArtifact(
  value: unknown,
  subtle: SubtleCrypto
): Promise<Record<string, unknown>> {
  const order = exactObject(value, ORDER_FIELDS, "Order");
  if (order.kind !== "nth.dao.trade.order" || order.protocol_version !== "1") {
    throw new Error("Order version is invalid");
  }
  const orderId = boundedString(order.order_id, "order_id", 1, 256);
  if (!ORDER_ID.test(orderId)) throw new Error("order_id is invalid");
  const snapshot = exactObject(order.snapshot, ORDER_SNAPSHOT_FIELDS, "Order snapshot");
  const offer = validateTradeOffer(snapshot.offer);
  if (!(await verifyOfferSnapshotSignature(offer, subtle, TRADE_OFFER_DOMAIN))) {
    throw new Error("Order Offer signature is invalid");
  }
  const proposal = await verifyProposalArtifact(snapshot.proposal, subtle);
  const acceptance = await verifyAcceptanceArtifact(snapshot.acceptance, subtle);
  const proposalDigest = await sha256Digest(proposal, subtle);
  const acceptanceDigest = await sha256Digest(acceptance, subtle);
  const offerDigest = await sha256Digest(offer, subtle);
  for (const [field, expected] of [
    ["proposal_digest", proposalDigest], ["acceptance_digest", acceptanceDigest],
    ["offer_digest", offerDigest],
  ] as const) {
    if (order[field] !== expected) throw new Error(`Order ${field} mismatch`);
  }
  if (
    proposal.offer_digest !== offerDigest ||
    proposal.offer_id !== offer.offer_id ||
    proposal.offer_revision !== offer.revision ||
    proposal.offer_publisher_did !== offer.publisher_did ||
    acceptance.proposal_digest !== proposalDigest
  ) {
    throw new Error("Order nested agreement binding is invalid");
  }
  for (const field of ["offer_digest", "maker_did", "taker_did", "rule_bindings"] as const) {
    if (!canonicalEqual(acceptance[field], proposal[field])) {
      throw new Error(`acceptance ${field} mismatch`);
    }
  }
  const acceptedAt = timestampNanos(acceptance.created_at, "acceptance.created_at");
  if (
    acceptedAt < timestampNanos(proposal.created_at, "proposal.created_at") ||
    acceptedAt >= timestampNanos(proposal.not_after, "proposal.not_after")
  ) {
    throw new Error("acceptance chronology is invalid");
  }
  const requiredRules = new Set(
    asArray(offer.rule_refs, "offer.rule_refs").map((item) => {
      const rule = exactObject(item, RULE_REF_FIELDS, "offer rule_ref");
      return `${rule.rule_id}\0${rule.digest}`;
    })
  );
  const proposalRules = new Set(
    validateRuleBindings(proposal.rule_bindings).map((item) => `${item.rule_id}\0${item.digest}`)
  );
  if ([...requiredRules].some((item) => !proposalRules.has(item))) {
    throw new Error("proposal omits an Offer Rule binding");
  }
  const policyDigests = exactObject(order.policy_digests, ORDER_POLICY_DIGEST_FIELDS, "policy_digests");
  if (
    order.maker_did !== proposal.maker_did ||
    order.taker_did !== proposal.taker_did ||
    !canonicalEqual(order.rule_bindings, proposal.rule_bindings) ||
    policyDigests.maker !== acceptance.maker_policy_digest ||
    policyDigests.taker !== proposal.taker_policy_digest ||
    order.created_at !== acceptance.created_at ||
    orderId !== `nth-trade-order-sha256:${proposalDigest.slice("sha256:".length)}`
  ) {
    throw new Error("Order top-level binding is invalid");
  }
  return order;
}

function validateExecutionContent(value: unknown, label: string): Record<string, unknown> {
  const content = exactObject(value, EXECUTION_CONTENT_FIELDS, label);
  if (typeof content.media_type !== "string" || !DISPUTE_MEDIA_TYPE.test(content.media_type)) {
    throw new Error(`${label}.media_type is invalid`);
  }
  digest(content.digest, `${label}.digest`);
  disputeSize(content.size_bytes, `${label}.size_bytes`);
  return content;
}

function executionGrants(order: Record<string, unknown>): Record<string, unknown>[] {
  const snapshot = asObject(order.snapshot, "Order snapshot");
  const proposal = asObject(snapshot.proposal, "Order proposal");
  const terms = asObject(proposal.terms, "Order terms");
  const extension = exactObject(terms["org.nthdao.execution/v1"], EXECUTION_TERMS_FIELDS, "execution terms");
  const values = asArray(extension.grants, "execution grants");
  if (values.length < 1 || values.length > 256) throw new Error("execution grants are invalid");
  let previous = "";
  return values.map((raw, index) => {
    const grant = exactObject(raw, EXECUTION_GRANT_FIELDS, `execution grant[${index}]`);
    const operationId = boundedString(grant.operation_id, "operation_id", 1, 128);
    if (!OPERATION_ID.test(operationId) || operationId <= previous) {
      throw new Error("execution grants must be sorted and unique");
    }
    previous = operationId;
    if (typeof grant.rule_id !== "string" || !RULE_ID.test(grant.rule_id)) throw new Error("grant rule_id is invalid");
    digest(grant.package_digest, "grant.package_digest");
    for (const field of ["hook_name", "hook_version"] as const) {
      if (typeof grant[field] !== "string" || !ASCII_TOKEN.test(grant[field])) throw new Error(`grant ${field} is invalid`);
    }
    if (!EXECUTOR_ROLES.has(grant.executor_role as string)) throw new Error("grant executor_role is invalid");
    return grant;
  });
}

async function verifyReceiptArtifact(
  value: unknown,
  order: Record<string, unknown>,
  subtle: SubtleCrypto
): Promise<Record<string, unknown>> {
  const receipt = exactObject(value, EXECUTION_RECEIPT_FIELDS, "Execution Receipt");
  if (receipt.kind !== "nth.dao.trade.execution-receipt" || receipt.protocol_version !== "1") {
    throw new Error("Execution Receipt version is invalid");
  }
  const executionId = boundedString(receipt.execution_id, "execution_id", 1, 256);
  if (!EXECUTION_ID.test(executionId) || receipt.order_id !== order.order_id) throw new Error("Receipt identity binding is invalid");
  const orderDigest = await sha256Digest(order, subtle);
  if (receipt.order_digest !== orderDigest) throw new Error("Receipt order_digest mismatch");
  const role = receipt.executor_role as string;
  const executorDid = boundedString(receipt.executor_did, "executor_did", 1, 256);
  decodeDidKey(executorDid);
  if (!EXECUTOR_ROLES.has(role) || executorDid !== order[`${role}_did`]) throw new Error("Receipt executor binding is invalid");
  const readiness = exactObject(receipt.readiness, EXECUTION_READINESS_FIELDS, "readiness");
  if (
    readiness.kind !== "nth.dao.trade.execution-readiness" ||
    readiness.protocol_version !== "1" || readiness.order_digest !== orderDigest ||
    receipt.readiness_digest !== await sha256Digest(readiness, subtle)
  ) {
    throw new Error("Receipt readiness binding is invalid");
  }
  digest(readiness.executor_policy_digest, "readiness.executor_policy_digest");
  const packages = asArray(readiness.ordered_package_digests, "readiness.ordered_package_digests");
  if (packages.some((item) => typeof item !== "string" || !DIGEST.test(item)) || new Set(packages).size !== packages.length) {
    throw new Error("readiness package digests are invalid");
  }
  for (const field of ["required_capabilities", "required_permissions", "execution_modes"] as const) {
    validateSortedUniqueStrings(readiness[field], `readiness.${field}`, 256, (item) => item.length <= 128 && /^[!-~]+$/.test(item));
  }
  disputeSize(readiness.resolved_resource_bytes, "readiness.resolved_resource_bytes");
  const adapter = exactObject(receipt.adapter, EXECUTION_ADAPTER_FIELDS, "adapter");
  if (
    typeof adapter.adapter_id !== "string" || !ADAPTER_ID.test(adapter.adapter_id) ||
    typeof adapter.adapter_version !== "string" || !SEMVER.test(adapter.adapter_version) ||
    typeof adapter.execution_mode !== "string" || !ASCII_TOKEN.test(adapter.execution_mode) ||
    !asArray(readiness.execution_modes, "execution_modes").includes(adapter.execution_mode)
  ) {
    throw new Error("Receipt adapter is invalid");
  }
  digest(adapter.adapter_digest, "adapter.adapter_digest");
  const operation = exactObject(receipt.operation, EXECUTION_OPERATION_FIELDS, "operation");
  const operationId = boundedString(operation.operation_id, "operation_id", 1, 128);
  if (!OPERATION_ID.test(operationId) || operation.executor_role !== role) throw new Error("Receipt operation binding is invalid");
  if (typeof operation.rule_id !== "string" || !RULE_ID.test(operation.rule_id)) throw new Error("operation.rule_id is invalid");
  for (const field of ["package_digest", "input_schema_digest", "output_schema_digest"] as const) digest(operation[field], `operation.${field}`);
  for (const field of ["hook_name", "hook_version"] as const) {
    if (typeof operation[field] !== "string" || !ASCII_TOKEN.test(operation[field])) throw new Error(`operation.${field} is invalid`);
  }
  validateExecutionContent(operation.input, "operation.input");
  if (!SIDE_EFFECTS.has(operation.side_effect as string)) throw new Error("operation.side_effect is invalid or requires a payment mandate");
  const grant = executionGrants(order).find((item) => item.operation_id === operationId);
  if (!grant || EXECUTION_GRANT_FIELDS.some((field) => operation[field] !== grant[field])) {
    throw new Error("Receipt operation is not authorized by the signed Order");
  }
  const orderPackages = new Set(validateRuleBindings(order.rule_bindings).map((item) => item.digest));
  if (packages.length !== orderPackages.size || packages.some((item) => !orderPackages.has(item))) {
    throw new Error("Receipt packages do not match Order bindings");
  }
  if (!EXECUTION_OUTCOMES.has(receipt.outcome as string)) throw new Error("Receipt outcome is invalid");
  validateExecutionContent(receipt.result, "result");
  const evidence = asArray(receipt.evidence, "evidence");
  if (evidence.length > 64) throw new Error("Receipt evidence exceeds 64 entries");
  const evidenceKeys = evidence.map((raw, index) => {
    const item = exactObject(raw, EXECUTION_EVIDENCE_FIELDS, `evidence[${index}]`);
    if (typeof item.evidence_type !== "string" || !/^[a-z][a-z0-9._-]{0,127}$/.test(item.evidence_type)) throw new Error("evidence_type is invalid");
    validateExecutionContent({ media_type: item.media_type, digest: item.digest, size_bytes: item.size_bytes }, `evidence[${index}]`);
    return `${item.evidence_type}\0${item.digest}`;
  });
  if (new Set(evidenceKeys).size !== evidenceKeys.length || evidenceKeys.some((item, index) => item !== [...evidenceKeys].sort()[index])) {
    throw new Error("Receipt evidence must be sorted and unique");
  }
  const started = disputeTimestampMicros(receipt.started_at, "started_at");
  const completed = disputeTimestampMicros(receipt.completed_at, "completed_at");
  if (readiness.evaluated_at !== receipt.started_at || completed < started) throw new Error("Receipt chronology is invalid");
  const expectedExecutionId = "nth-trade-execution-sha256:" + (await sha256Digest({
    executor_did: executorDid, operation_id: operationId, order_digest: orderDigest,
  }, subtle)).slice("sha256:".length);
  if (executionId !== expectedExecutionId) throw new Error("execution_id binding mismatch");
  await verifyArtifactSignature(
    receipt, executorDid, "tradeExecution",
    boundedString(receipt.completed_at, "completed_at", 1, 35),
    TRADE_EXECUTION_RECEIPT_DOMAIN, subtle
  );
  return receipt;
}

async function verifyReviewArtifact(
  value: unknown,
  receipt: Record<string, unknown>,
  order: Record<string, unknown>,
  subtle: SubtleCrypto
): Promise<Record<string, unknown>> {
  const review = exactObject(value, RECEIPT_REVIEW_FIELDS, "Receipt Review");
  if (review.kind !== "nth.dao.trade.receipt-review" || review.protocol_version !== "1") throw new Error("Receipt Review version is invalid");
  const reviewerDid = boundedString(review.reviewer_did, "reviewer_did", 1, 256);
  decodeDidKey(reviewerDid);
  const reviewerRole = review.reviewer_role as string;
  const expectedRole = receipt.executor_role === "maker" ? "taker" : "maker";
  const orderDigest = await sha256Digest(order, subtle);
  const receiptDigest = await sha256Digest(receipt, subtle);
  if (
    !REVIEW_ID.test(review.review_id as string) || !EXECUTION_ID.test(review.execution_id as string) ||
    review.order_id !== order.order_id || review.order_digest !== orderDigest ||
    review.execution_id !== receipt.execution_id || review.receipt_digest !== receiptDigest ||
    reviewerRole !== expectedRole || reviewerDid !== order[`${expectedRole}_did`]
  ) {
    throw new Error("Receipt Review binding is invalid");
  }
  for (const field of ["verifier_policy_digest", "adapter_policy_digest"] as const) digest(review[field], field);
  const expectedReviewId = "nth-trade-review-sha256:" + (await sha256Digest({
    receipt_digest: receiptDigest, reviewer_did: reviewerDid,
  }, subtle)).slice("sha256:".length);
  if (review.review_id !== expectedReviewId) throw new Error("review_id binding mismatch");
  if (!new Set(["accepted", "rejected", "disputed"]).has(review.decision as string)) throw new Error("Review decision is invalid");
  const reasons = validateSortedUniqueStrings(review.reason_codes, "reason_codes", 32, (item) => REVIEW_REASON.test(item));
  if (review.decision !== "accepted" && reasons.length === 0) throw new Error("negative Review requires reason_codes");
  if (review.decision === "accepted" && receipt.outcome !== "succeeded") throw new Error("only succeeded Receipt may be accepted");
  if (disputeTimestampMicros(review.reviewed_at, "reviewed_at") < disputeTimestampMicros(receipt.completed_at, "receipt.completed_at")) {
    throw new Error("Receipt Review predates Receipt completion");
  }
  await verifyArtifactSignature(
    review, reviewerDid, "tradeReceiptReview",
    boundedString(review.reviewed_at, "reviewed_at", 1, 35),
    TRADE_RECEIPT_REVIEW_DOMAIN, subtle
  );
  return review;
}

export async function createVerifiedTradeDisputeArtifacts(
  artifacts: Readonly<{ order: unknown; receipt: unknown; review: unknown }>,
  subtle: SubtleCrypto = globalThis.crypto.subtle
): Promise<VerifiedTradeDisputeArtifacts> {
  const order = frozenCanonicalTradeObject(artifacts.order);
  const receipt = frozenCanonicalTradeObject(artifacts.receipt);
  const review = frozenCanonicalTradeObject(artifacts.review);
  const verifiedOrder = await verifyOrderArtifact(order, subtle);
  const verifiedReceipt = await verifyReceiptArtifact(receipt, verifiedOrder, subtle);
  await verifyReviewArtifact(review, verifiedReceipt, verifiedOrder, subtle);
  const bundle = Object.freeze({ order, receipt, review });
  verifiedTradeDisputeArtifactBundles.add(bundle);
  return bundle;
}

function requireVerifiedTradeDisputeArtifacts(
  value: VerifiedTradeDisputeArtifacts
): VerifiedTradeDisputeArtifacts {
  if (
    value === null ||
    typeof value !== "object" ||
    !verifiedTradeDisputeArtifactBundles.has(value)
  ) {
    throw new Error(
      "artifacts must come from createVerifiedTradeDisputeArtifacts"
    );
  }
  return value;
}

export type TradeDisputeStatementVerificationContext = {
  artifacts: VerifiedTradeDisputeArtifacts;
  observedAt: string;
  clockSkewSeconds?: number;
  resolvedRulePackage?: unknown;
  requireRuleResolution?: boolean;
};

export type TradeDisputeStatementVerificationResult = {
  valid: boolean;
  reason: string;
};

function disputeTimestampMicros(value: unknown, label: string): bigint {
  const text = boundedString(value, label, 1, 35);
  const match = DISPUTE_TIMESTAMP.exec(text);
  if (!match || match[2] === "000000") {
    throw new Error(`${label} must be a canonical UTC RFC3339 timestamp`);
  }
  const base = match[1] ?? "";
  if (Number(base.slice(0, 4)) < 1) {
    throw new Error(`${label} is not a real timestamp`);
  }
  const date = new Date(`${base}Z`);
  if (Number.isNaN(date.getTime()) || date.toISOString().slice(0, 19) !== base) {
    throw new Error(`${label} is not a real timestamp`);
  }
  const micros = BigInt(match[2] ?? "0");
  return BigInt(date.getTime()) * 1_000n + micros;
}

function disputeSize(value: unknown, label: string): number {
  if (
    typeof value !== "number" ||
    !Number.isSafeInteger(value) ||
    value < 0 ||
    value > MAX_DISPUTE_CONTENT_BYTES
  ) {
    throw new Error(`${label} is invalid`);
  }
  return value;
}

function sortedUniqueStrings(
  value: unknown,
  label: string,
  limit: number,
  validator: RegExp
): string[] {
  const items = asArray(value, label);
  if (
    items.length > limit ||
    items.some((item) => typeof item !== "string" || !validator.test(item))
  ) {
    throw new Error(`${label} must be bounded, sorted, and unique`);
  }
  const strings = items as string[];
  const sorted = [...new Set(strings)].sort();
  if (
    sorted.length !== strings.length ||
    strings.some((item, index) => item !== sorted[index])
  ) {
    throw new Error(`${label} must be bounded, sorted, and unique`);
  }
  return strings;
}

type DisputeContentBinding = {
  digest: string;
  mediaType: string;
  size: number;
};

function validateDisputeClaim(
  value: unknown,
  statementType: string
): DisputeContentBinding | null {
  if (value === null) {
    if (statementType !== "evidence") {
      throw new Error("response and remedy statements require a typed claim");
    }
    return null;
  }
  if (statementType === "evidence") {
    throw new Error("evidence statements cannot contain a claim");
  }
  const claim = exactObject(value, DISPUTE_CLAIM_FIELDS, "claim");
  const claimType = boundedString(claim.claim_type, "claim.claim_type", 1, 128);
  if (!DISPUTE_TOKEN.test(claimType)) throw new Error("claim.claim_type is invalid");
  const mediaType = boundedString(claim.media_type, "claim.media_type", 1, 127);
  if (!DISPUTE_MEDIA_TYPE.test(mediaType)) {
    throw new Error("claim.media_type is invalid");
  }
  const claimDigest = digest(claim.digest, "claim.digest");
  const size = disputeSize(claim.size, "claim.size");
  if (claim.schema_digest !== null) digest(claim.schema_digest, "claim.schema_digest");
  return { digest: claimDigest, mediaType, size };
}

type DisputeEvidenceBinding = DisputeContentBinding & { purpose: string };

function compareEvidence(
  left: DisputeEvidenceBinding,
  right: DisputeEvidenceBinding
): number {
  for (const pair of [
    [left.purpose, right.purpose],
    [left.digest, right.digest],
    [left.mediaType, right.mediaType],
  ] as const) {
    if (pair[0] < pair[1]) return -1;
    if (pair[0] > pair[1]) return 1;
  }
  return left.size - right.size;
}

function validateDisputeEvidence(value: unknown): DisputeEvidenceBinding[] {
  const items = asArray(value, "evidence");
  if (items.length > 32) throw new Error("evidence must be a bounded list");
  const bindings = items.map((raw, index) => {
    const item = exactObject(raw, DISPUTE_EVIDENCE_FIELDS, `evidence[${index}]`);
    const purpose = boundedString(
      item.purpose,
      `evidence[${index}].purpose`,
      1,
      128
    );
    if (!DISPUTE_TOKEN.test(purpose)) {
      throw new Error(`evidence[${index}].purpose is invalid`);
    }
    const mediaType = boundedString(
      item.media_type,
      `evidence[${index}].media_type`,
      1,
      127
    );
    if (!DISPUTE_MEDIA_TYPE.test(mediaType)) {
      throw new Error(`evidence[${index}].media_type is invalid`);
    }
    return {
      purpose,
      digest: digest(item.digest, `evidence[${index}].digest`),
      mediaType,
      size: disputeSize(item.size, `evidence[${index}].size`),
    };
  });
  const sorted = [...bindings].sort(compareEvidence);
  if (
    bindings.some((item, index) => compareEvidence(item, sorted[index]!) !== 0) ||
    bindings.some(
      (item, index) => index > 0 && compareEvidence(item, bindings[index - 1]!) === 0
    )
  ) {
    throw new Error("evidence must be sorted and contain no duplicate entries");
  }
  const metadata = new Map<string, string>();
  let totalSize = 0;
  for (const item of bindings) {
    totalSize += item.size;
    if (totalSize > MAX_DISPUTE_TOTAL_EVIDENCE_BYTES) {
      throw new Error("declared dispute evidence exceeds its total byte limit");
    }
    const current = `${item.mediaType}\0${item.size}`;
    const previous = metadata.get(item.digest);
    if (previous !== undefined && previous !== current) {
      throw new Error("one evidence digest cannot declare conflicting metadata");
    }
    metadata.set(item.digest, current);
  }
  return bindings;
}

function validateTradeDisputeStatementShape(
  value: unknown
): Record<string, unknown> {
  const document = exactObject(
    JSON.parse(new TextDecoder().decode(tradeCanonicalBytes(value))),
    DISPUTE_STATEMENT_FIELDS,
    "trade dispute statement"
  );
  if (
    document.kind !== "nth.dao.trade.dispute-statement" ||
    document.protocol_version !== "1"
  ) {
    throw new Error("unsupported trade dispute statement protocol");
  }
  if (typeof document.statement_id !== "string" || !DISPUTE_STATEMENT_ID.test(document.statement_id)) {
    throw new Error("statement_id is invalid");
  }
  if (typeof document.dispute_id !== "string" || !DISPUTE_ID.test(document.dispute_id)) {
    throw new Error("dispute_id is invalid");
  }
  for (const field of ["order_digest", "receipt_digest", "review_digest"] as const) {
    digest(document[field], field);
  }
  if (typeof document.review_id !== "string" || !DISPUTE_REVIEW_ID.test(document.review_id)) {
    throw new Error("review_id is invalid");
  }
  if (typeof document.author_did !== "string") throw new Error("author_did is invalid");
  decodeDidKey(document.author_did);
  if (document.author_role !== "maker" && document.author_role !== "taker") {
    throw new Error("author_role is invalid");
  }
  if (
    document.statement_type !== "response" &&
    document.statement_type !== "evidence" &&
    document.statement_type !== "remedy-proposal"
  ) {
    throw new Error("statement_type is invalid");
  }
  sortedUniqueStrings(
    document.parent_statement_digests,
    "parent_statement_digests",
    64,
    DIGEST
  );
  const reasons = sortedUniqueStrings(
    document.reason_codes,
    "reason_codes",
    32,
    DISPUTE_REASON
  );
  const claim = validateDisputeClaim(document.claim, document.statement_type);
  const evidence = validateDisputeEvidence(document.evidence);
  if (document.statement_type === "evidence" && evidence.length === 0) {
    throw new Error("evidence statements require at least one evidence reference");
  }
  if (document.statement_type !== "evidence" && reasons.length === 0) {
    throw new Error("response and remedy statements require a reason code");
  }
  if (claim !== null) {
    for (const item of evidence) {
      if (
        item.digest === claim.digest &&
        (item.mediaType !== claim.mediaType || item.size !== claim.size)
      ) {
        throw new Error("claim and evidence metadata conflict for one digest");
      }
    }
  }
  if (document.rule_action !== null) {
    const action = exactObject(
      document.rule_action,
      DISPUTE_RULE_ACTION_FIELDS,
      "rule_action"
    );
    if (typeof action.rule_id !== "string" || !RULE_ID.test(action.rule_id)) {
      throw new Error("rule_action.rule_id is invalid");
    }
    digest(action.digest, "rule_action.digest");
    if (typeof action.hook !== "string" || !DISPUTE_HOOK.test(action.hook)) {
      throw new Error("rule_action.hook is invalid");
    }
    if (
      typeof action.hook_version !== "string" ||
      !DISPUTE_HOOK_VERSION.test(action.hook_version)
    ) {
      throw new Error("rule_action.hook_version is invalid");
    }
  }
  disputeTimestampMicros(document.created_at, "created_at");
  const proof = exactObject(document.proof, PROOF_FIELDS, "proof");
  if (
    proof.type !== "Ed25519Signature2020" ||
    proof.proof_purpose !== "tradeDisputeStatement" ||
    proof.created !== document.created_at ||
    proof.verification_method !==
      `${document.author_did}#${document.author_did.slice("did:key:".length)}` ||
    typeof proof.proof_value !== "string"
  ) {
    throw new Error("trade dispute statement proof is invalid");
  }
  decodeBase64Url(proof.proof_value);
  return document;
}

async function sha256Digest(
  value: unknown,
  subtle: SubtleCrypto
): Promise<string> {
  const hash = new Uint8Array(
    await subtle.digest("SHA-256", asArrayBuffer(tradeCanonicalBytes(value)))
  );
  return `sha256:${Array.from(hash, (byte) =>
    byte.toString(16).padStart(2, "0")
  ).join("")}`;
}

async function validateResolvedDisputePackage(
  value: unknown,
  action: Record<string, unknown>,
  subtle: SubtleCrypto
): Promise<void> {
  const rulePackage = exactObject(value, DISPUTE_PACKAGE_FIELDS, "resolved Rule Package");
  if (rulePackage.digest !== action.digest) {
    throw new Error("rule_action package digest mismatch");
  }
  const manifest = asObject(rulePackage.manifest, "resolved Rule Package manifest");
  if (!(await verifyManifestSignature(manifest, subtle))) {
    throw new Error("rule_action package manifest signature is invalid");
  }
  if ((await sha256Digest(manifest, subtle)) !== action.digest) {
    throw new Error("rule_action package manifest digest mismatch");
  }
  if (manifest.rule_id !== action.rule_id) {
    throw new Error("rule_action rule_id does not match the resolved package");
  }
  const declarations = asArray(manifest.resources, "resolved Rule Package manifest.resources");
  const declared = new Map<string, number>();
  for (const [index, raw] of declarations.entries()) {
    const item = asObject(raw, `resolved Rule Package manifest.resources[${index}]`);
    const resourceDigest = digest(item.digest, `manifest.resources[${index}].digest`);
    const size = item.size;
    if (typeof size !== "number" || !Number.isSafeInteger(size) || size < 0) {
      throw new Error(`manifest.resources[${index}].size is invalid`);
    }
    const previous = declared.get(resourceDigest);
    if (previous !== undefined && previous !== size) {
      throw new Error("resolved Rule Package declares conflicting resource sizes");
    }
    declared.set(resourceDigest, size);
  }
  const supplied = new Set<string>();
  for (const [index, raw] of asArray(rulePackage.resources, "resolved Rule Package resources").entries()) {
    const item = exactObject(raw, DISPUTE_PACKAGE_RESOURCE_FIELDS, `resources[${index}]`);
    const resourceDigest = digest(item.digest, `resources[${index}].digest`);
    if (supplied.has(resourceDigest)) throw new Error("resolved Rule Package repeats a resource");
    if (typeof item.bytes_hex !== "string" || !/^(?:[0-9a-f]{2})*$/.test(item.bytes_hex)) {
      throw new Error(`resources[${index}].bytes_hex is invalid`);
    }
    const payload = Uint8Array.from(
      item.bytes_hex.match(/.{2}/g) ?? [],
      (pair) => Number.parseInt(pair, 16)
    );
    const hash = new Uint8Array(await subtle.digest("SHA-256", asArrayBuffer(payload)));
    const actual = `sha256:${Array.from(hash, (byte) =>
      byte.toString(16).padStart(2, "0")
    ).join("")}`;
    if (actual !== resourceDigest || declared.get(resourceDigest) !== payload.byteLength) {
      throw new Error("resolved Rule Package resource bytes do not match the manifest");
    }
    supplied.add(resourceDigest);
  }
  if (supplied.size !== declared.size || [...declared.keys()].some((key) => !supplied.has(key))) {
    throw new Error("resolved Rule Package resources are incomplete");
  }
  const hooks = asArray(manifest.hook_contracts, "resolved Rule Package hook_contracts");
  if (
    !hooks.some((raw) => {
      const hook = asObject(raw, "resolved Rule Package hook contract");
      return hook.name === action.hook && hook.version === action.hook_version;
    })
  ) {
    throw new Error("rule_action hook name/version is absent from the package");
  }
}

export async function verifyTradeDisputeStatement(
  statement: unknown,
  context: TradeDisputeStatementVerificationContext,
  subtle: SubtleCrypto = globalThis.crypto.subtle
): Promise<TradeDisputeStatementVerificationResult> {
  try {
    const document = validateTradeDisputeStatementShape(statement);
    if (!(await verifyTradeDisputeStatementSignature(document, subtle))) {
      throw new Error("trade dispute statement signature is invalid");
    }
    const binding = { ...document };
    delete binding.statement_id;
    delete binding.proof;
    const expectedStatementId =
      "nth-trade-dispute-statement-sha256:" +
      (await sha256Digest(binding, subtle)).slice("sha256:".length);
    if (document.statement_id !== expectedStatementId) {
      throw new Error("statement_id does not match the statement binding");
    }

    const artifacts = requireVerifiedTradeDisputeArtifacts(context.artifacts);
    const order = asObject(artifacts.order, "verified Order");
    const receipt = asObject(artifacts.receipt, "verified Execution Receipt");
    const review = asObject(artifacts.review, "verified Receipt Review");
    const expectedDisputeId =
      "nth-trade-dispute-sha256:" +
      (await sha256Digest({ review_id: review.review_id }, subtle)).slice("sha256:".length);
    const bindings = [
      ["dispute_id", expectedDisputeId],
      ["order_digest", await sha256Digest(order, subtle)],
      ["receipt_digest", await sha256Digest(receipt, subtle)],
      ["review_digest", await sha256Digest(review, subtle)],
      ["review_id", review.review_id],
    ] as const;
    for (const [field, expected] of bindings) {
      if (document[field] !== expected) {
        throw new Error(`trade dispute statement ${field} binding mismatch`);
      }
    }
    if (review.decision !== "disputed") {
      throw new Error("trade dispute statements require a disputed Receipt Review");
    }
    const role = document.author_role as "maker" | "taker";
    if (document.author_did !== order[`${role}_did`]) {
      throw new Error("author_did does not match author_role in the signed Order");
    }
    if (document.statement_type === "response" && role !== receipt.executor_role) {
      throw new Error("a response must be signed by the Receipt executor");
    }
    if (
      disputeTimestampMicros(document.created_at, "created_at") <
      disputeTimestampMicros(review.reviewed_at, "review.reviewed_at")
    ) {
      throw new Error("trade dispute statement predates the disputed Review");
    }
    const skew = context.clockSkewSeconds ?? 300;
    if (!Number.isFinite(skew) || skew < 0 || skew > 86_400) {
      throw new Error("clockSkewSeconds must be finite and between 0 and 86400");
    }
    const observed = disputeTimestampMicros(context.observedAt, "observedAt");
    const created = disputeTimestampMicros(document.created_at, "created_at");
    if (created > observed + BigInt(Math.round(skew * 1_000_000))) {
      throw new Error("trade dispute statement is too far in the future");
    }

    if (document.rule_action !== null) {
      const action = asObject(document.rule_action, "rule_action");
      const signedBindings = asArray(order.rule_bindings, "Order rule_bindings");
      const bound = signedBindings.some((raw) => {
        const item = asObject(raw, "Order rule binding");
        return item.rule_id === action.rule_id && item.digest === action.digest;
      });
      if (!bound) throw new Error("rule_action is outside the signed Order rule bindings");
      if (context.resolvedRulePackage === undefined) {
        if (context.requireRuleResolution !== false) {
          throw new Error("rule_action requires an exact-digest resolved Rule Package");
        }
      } else {
        await validateResolvedDisputePackage(
          context.resolvedRulePackage,
          action,
          subtle
        );
      }
    }
    return { valid: true, reason: "ok" };
  } catch (error) {
    return {
      valid: false,
      reason: error instanceof Error ? error.message : "invalid trade dispute statement",
    };
  }
}

export type TradeDisputeStatementDeliveryVerificationContext = {
  artifacts: VerifiedTradeDisputeArtifacts;
  recipientDid: string;
  observedAt: string;
  maxTtlSeconds?: number;
  clockSkewSeconds?: number;
  resolvedRulePackage?: unknown;
};

function boundedTransportSeconds(value: number | undefined, fallback: number): bigint {
  const seconds = value ?? fallback;
  if (!Number.isFinite(seconds) || seconds < 0 || seconds > 86_400) {
    throw new Error("transport seconds must be finite and between 0 and 86400");
  }
  return BigInt(Math.trunc(seconds * 1_000_000_000));
}

function validateTransportProof(
  document: Record<string, unknown>,
  signerField: "sender_did" | "receiver_did",
  purpose: string,
  createdField: "created_at" | "received_at"
): { signerDid: string; signature: Uint8Array } {
  const proof = exactObject(document.proof, TRANSPORT_PROOF_FIELDS, "transport proof");
  const signerDid = boundedString(document[signerField], signerField, 1, 256);
  decodeDidKey(signerDid);
  if (
    proof.type !== "Ed25519Signature2020" ||
    proof.proof_purpose !== purpose ||
    proof.created !== document[createdField] ||
    proof.verification_method !==
      `${signerDid}#${signerDid.slice("did:key:".length)}`
  ) {
    throw new Error("transport proof binding is invalid");
  }
  return {
    signerDid,
    signature: decodeBase64Url(
      boundedString(proof.proof_value, "proof.proof_value", 86, 86)
    ),
  };
}

async function verifyTransportSignature(
  document: Record<string, unknown>,
  signerField: "sender_did" | "receiver_did",
  purpose: string,
  createdField: "created_at" | "received_at",
  domain: string,
  subtle: SubtleCrypto
): Promise<void> {
  const { signerDid, signature } = validateTransportProof(
    document,
    signerField,
    purpose,
    createdField
  );
  const key = await subtle.importKey(
    "raw",
    asArrayBuffer(decodeDidKey(signerDid)),
    { name: "Ed25519" },
    false,
    ["verify"]
  );
  const valid = await subtle.verify(
    { name: "Ed25519" },
    key,
    asArrayBuffer(signature),
    asArrayBuffer(manifestSigningInput(document, domain))
  );
  if (!valid) throw new Error("transport signature is invalid");
}

function oppositeOrderParty(
  order: Record<string, unknown>,
  senderDid: string
): string {
  if (senderDid === order.maker_did && typeof order.taker_did === "string") {
    return order.taker_did;
  }
  if (senderDid === order.taker_did && typeof order.maker_did === "string") {
    return order.maker_did;
  }
  throw new Error("transport sender is not an Order party");
}

export async function verifyTradeDisputeStatementDelivery(
  delivery: unknown,
  context: TradeDisputeStatementDeliveryVerificationContext,
  subtle: SubtleCrypto = globalThis.crypto.subtle,
  domain = TRADE_DISPUTE_STATEMENT_DELIVERY_DOMAIN
): Promise<TradeDisputeStatementVerificationResult> {
  try {
    const document = exactObject(
      JSON.parse(new TextDecoder().decode(tradeCanonicalBytes(delivery))),
      DISPUTE_DELIVERY_FIELDS,
      "Trade Dispute Statement Delivery"
    );
    if (
      document.kind !== "nth.dao.trade.dispute-statement-delivery" ||
      document.protocol_version !== "1" ||
      typeof document.delivery_id !== "string" ||
      !DISPUTE_DELIVERY_ID.test(document.delivery_id) ||
      typeof document.nonce !== "string" ||
      !DISPUTE_NONCE.test(document.nonce)
    ) {
      throw new Error("Trade Dispute Statement Delivery shape is invalid");
    }
    for (const field of [
      "order_digest", "receipt_digest", "review_digest", "statement_digest",
    ] as const) digest(document[field], field);
    const senderDid = boundedString(document.sender_did, "sender_did", 1, 256);
    const recipientDid = boundedString(document.recipient_did, "recipient_did", 1, 256);
    decodeDidKey(senderDid);
    decodeDidKey(recipientDid);
    if (senderDid === recipientDid || recipientDid !== context.recipientDid) {
      throw new Error("delivery recipient does not match this node");
    }
    const binding = { ...document };
    delete binding.delivery_id;
    delete binding.proof;
    const expectedId =
      "nth:trade:dispute-statement-delivery:sha256:" +
      (await sha256Digest(binding, subtle)).slice("sha256:".length);
    if (document.delivery_id !== expectedId) {
      throw new Error("delivery_id does not match delivery content");
    }
    const artifacts = requireVerifiedTradeDisputeArtifacts(context.artifacts);
    const order = asObject(artifacts.order, "verified Order");
    const receipt = asObject(artifacts.receipt, "verified Execution Receipt");
    const review = asObject(artifacts.review, "verified Receipt Review");
    const expectedBindings = [
      ["order_digest", await sha256Digest(order, subtle)],
      ["receipt_digest", await sha256Digest(receipt, subtle)],
      ["review_digest", await sha256Digest(review, subtle)],
      ["statement_digest", await sha256Digest(document.statement, subtle)],
    ] as const;
    for (const [field, expected] of expectedBindings) {
      if (document[field] !== expected) throw new Error(`${field} binding mismatch`);
    }
    const statementResult = await verifyTradeDisputeStatement(
      document.statement,
      {
        artifacts,
        observedAt: boundedString(document.created_at, "created_at", 1, 35),
        clockSkewSeconds: 0,
        requireRuleResolution: false,
      },
      subtle
    );
    if (!statementResult.valid) {
      throw new Error(`embedded Statement is invalid: ${statementResult.reason}`);
    }
    const statement = asObject(document.statement, "embedded Statement");
    if (statement.author_did !== senderDid) {
      throw new Error("sender_did does not match Statement author");
    }
    if (oppositeOrderParty(order, senderDid) !== recipientDid) {
      throw new Error("recipient_did is not the opposing Order party");
    }
    const created = timestampNanos(document.created_at, "created_at");
    const expiry = timestampNanos(document.not_after, "not_after");
    const statementCreated = timestampNanos(statement.created_at, "statement.created_at");
    const observed = timestampNanos(context.observedAt, "observedAt");
    const skew = boundedTransportSeconds(context.clockSkewSeconds, 300);
    const ttl = boundedTransportSeconds(context.maxTtlSeconds, 600);
    if (expiry <= created || created < statementCreated) {
      throw new Error("delivery chronology is invalid");
    }
    if (expiry - created > ttl) throw new Error("delivery lifetime exceeds limit");
    if (observed < created - skew) throw new Error("delivery was created too far in the future");
    if (observed > expiry + skew) throw new Error("delivery has expired");
    await verifyTransportSignature(
      document,
      "sender_did",
      "tradeDisputeStatementDelivery",
      "created_at",
      domain,
      subtle
    );
    return { valid: true, reason: "ok" };
  } catch (error) {
    return {
      valid: false,
      reason: error instanceof Error ? error.message : "invalid statement delivery",
    };
  }
}

export async function verifyTradeDisputeStatementAcknowledgement(
  acknowledgement: unknown,
  delivery: unknown,
  context: TradeDisputeStatementDeliveryVerificationContext,
  subtle: SubtleCrypto = globalThis.crypto.subtle,
  domain = TRADE_DISPUTE_STATEMENT_ACKNOWLEDGEMENT_DOMAIN
): Promise<TradeDisputeStatementVerificationResult> {
  try {
    const canonical = tradeCanonicalBytes(acknowledgement);
    if (canonical.byteLength > MAX_DISPUTE_ACK_BYTES) {
      throw new Error("acknowledgement exceeds byte limit");
    }
    const document = exactObject(
      JSON.parse(new TextDecoder().decode(canonical)),
      DISPUTE_ACK_FIELDS,
      "Trade Dispute Statement Acknowledgement"
    );
    if (
      document.kind !== "nth.dao.trade.dispute-statement-acknowledgement" ||
      document.protocol_version !== "1" ||
      document.status !== "retained-claim-not-adjudicated" ||
      typeof document.audit_event_id !== "string" ||
      !EVENT_ID.test(document.audit_event_id)
    ) {
      throw new Error("Trade Dispute Statement Acknowledgement shape is invalid");
    }
    const receivedAt = boundedString(document.received_at, "received_at", 1, 35);
    const verifiedDelivery = await verifyTradeDisputeStatementDelivery(
      delivery,
      { ...context, observedAt: receivedAt },
      subtle
    );
    if (!verifiedDelivery.valid) {
      throw new Error(`Delivery is invalid: ${verifiedDelivery.reason}`);
    }
    const deliveryDocument = asObject(delivery, "Delivery");
    const expected = {
      delivery_id: deliveryDocument.delivery_id,
      delivery_digest: await sha256Digest(deliveryDocument, subtle),
      order_digest: deliveryDocument.order_digest,
      receipt_digest: deliveryDocument.receipt_digest,
      review_digest: deliveryDocument.review_digest,
      statement_digest: deliveryDocument.statement_digest,
      sender_did: deliveryDocument.sender_did,
      receiver_did: deliveryDocument.recipient_did,
    };
    for (const [field, value] of Object.entries(expected)) {
      if (document[field] !== value) throw new Error(`${field} does not match Delivery`);
    }
    const received = timestampNanos(receivedAt, "received_at");
    const created = timestampNanos(deliveryDocument.created_at, "delivery.created_at");
    const expiry = timestampNanos(deliveryDocument.not_after, "delivery.not_after");
    const observed = timestampNanos(context.observedAt, "observedAt");
    const skew = boundedTransportSeconds(context.clockSkewSeconds, 300);
    if (received < created - skew || received > expiry + skew) {
      throw new Error("acknowledgement chronology is outside Delivery lifetime");
    }
    if (received > observed + skew) {
      throw new Error("acknowledgement was created too far in the future");
    }
    await verifyTransportSignature(
      document,
      "receiver_did",
      "tradeDisputeStatementAcknowledgement",
      "received_at",
      domain,
      subtle
    );
    return { valid: true, reason: "ok" };
  } catch (error) {
    return {
      valid: false,
      reason: error instanceof Error ? error.message : "invalid acknowledgement",
    };
  }
}

async function verifyOfferSnapshotSignature(
  document: Record<string, unknown>,
  subtle: SubtleCrypto,
  domain: string
): Promise<boolean> {
  const proof = asObject(document.proof, "proof");
  if (
    typeof document.publisher_did !== "string" ||
    typeof proof.proof_value !== "string"
  ) {
    return false;
  }
  const keyBytes = decodeDidKey(document.publisher_did);
  const signature = decodeBase64Url(proof.proof_value);
  const key = await subtle.importKey(
    "raw",
    asArrayBuffer(keyBytes),
    { name: "Ed25519" },
    false,
    ["verify"]
  );
  return await subtle.verify(
    { name: "Ed25519" },
    key,
    asArrayBuffer(signature),
    asArrayBuffer(offerSigningInput(document, domain))
  );
}

export async function verifyOffer(
  offer: unknown,
  subtle: SubtleCrypto = globalThis.crypto.subtle,
  domain = TRADE_OFFER_DOMAIN
): Promise<boolean> {
  try {
    const snapshot = validateTradeOffer(offer);
    return await verifyOfferSnapshotSignature(snapshot, subtle, domain);
  } catch {
    return false;
  }
}

export type OfferActivity =
  | "active"
  | "expired"
  | "not_yet_active"
  | "withdrawn"
  | "invalid";

export async function evaluateTradeOffer(
  offer: unknown,
  at: Date = new Date(),
  subtle: SubtleCrypto = globalThis.crypto.subtle
): Promise<{ active: boolean; reason: OfferActivity }> {
  if (Number.isNaN(at.getTime())) return { active: false, reason: "invalid" };
  try {
    const snapshot = validateTradeOffer(offer);
    if (!(await verifyOfferSnapshotSignature(snapshot, subtle, TRADE_OFFER_DOMAIN))) {
      return { active: false, reason: "invalid" };
    }
    const moment = BigInt(at.getTime()) * 1_000_000n;
    if (moment < timestampNanos(snapshot.published_at, "published_at")) {
      return { active: false, reason: "not_yet_active" };
    }
    if (
      snapshot.not_after !== null &&
      moment >= timestampNanos(snapshot.not_after, "not_after")
    ) {
      return { active: false, reason: "expired" };
    }
    if (snapshot.state === "withdrawn") {
      return { active: false, reason: "withdrawn" };
    }
    return { active: true, reason: "active" };
  } catch {
    return { active: false, reason: "invalid" };
  }
}

export async function manifestDigest(
  manifest: unknown,
  subtle: SubtleCrypto = globalThis.crypto.subtle
): Promise<string> {
  const digest = new Uint8Array(
    await subtle.digest("SHA-256", asArrayBuffer(tradeCanonicalBytes(manifest)))
  );
  return `sha256:${Array.from(digest, (byte) => byte.toString(16).padStart(2, "0")).join("")}`;
}

export async function offerDigest(
  offer: unknown,
  subtle: SubtleCrypto = globalThis.crypto.subtle
): Promise<string> {
  const canonical = tradeCanonicalBytes(offer);
  const snapshot = JSON.parse(new TextDecoder().decode(canonical));
  try {
    validateOfferSnapshot(asObject(snapshot, "offer"));
  } catch {
    throw new Error("offer semantics invalid");
  }
  if (!(await verifyOfferSnapshotSignature(snapshot, subtle, TRADE_OFFER_DOMAIN))) {
    throw new Error("offer signature invalid");
  }
  const digest = new Uint8Array(
    await subtle.digest("SHA-256", asArrayBuffer(canonical))
  );
  return `sha256:${Array.from(digest, (byte) => byte.toString(16).padStart(2, "0")).join("")}`;
}
