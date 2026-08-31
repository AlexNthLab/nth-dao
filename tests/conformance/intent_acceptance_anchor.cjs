// Independent verifier of the bounded hash-only anchor profile, not an SDK.
const fs = require('node:fs');
const crypto = require('node:crypto');
const { ed25519 } = require('@noble/curves/ed25519.js');
class InvalidAnchor extends Error {}
function check(ok, reason) { if (!ok) throw new InvalidAnchor(reason); }
if (JSON.parse('0', (_k, _v, context) => context?.source) !== '0') {
  throw new Error('Conformance requires native JSON.parse source context');
}
function parse(raw) {
  return JSON.parse(raw, (_key, value, context) => {
    if (typeof value === 'number') check(/^-?(?:0|[1-9][0-9]*)$/.test(context.source), 'integer token');
    return value;
  });
}
function canonical(value) {
  if (Array.isArray(value)) return '[' + value.map(canonical).join(',') + ']';
  if (value && typeof value === 'object') return '{' + Object.keys(value).sort().map(k => JSON.stringify(k) + ':' + canonical(value[k])).join(',') + '}';
  return JSON.stringify(value);
}
const hash = value => crypto.createHash('sha256').update(value).digest('hex');
const digest = value => 'sha256:' + hash(canonical(value));
const safe = (value, min) => typeof value === 'number' && Number.isSafeInteger(value) && value >= min;
const isHash = value => typeof value === 'string' && /^sha256:[0-9a-f]{64}$/.test(value) && value.length === 71;
function fields(object, names) {
  check(object !== null && typeof object === 'object' && !Array.isArray(object), 'object');
  check(canonical(Object.keys(object).sort()) === canonical([...names].sort()), 'closed fields');
}
function encodeDid(pub) {
  const alphabet = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz';
  let n = BigInt('0x' + Buffer.concat([Buffer.from([0xed, 1]), pub]).toString('hex')), out = '';
  while (n) { out = alphabet[Number(n % 58n)] + out; n /= 58n; }
  return 'did:key:z' + out;
}
const vectors = parse(fs.readFileSync(0, 'utf8'));
const key = Buffer.from(vectors.expected_public_key_hex, 'hex');
check(key.length === 32 && encodeDid(key) === vectors.expected_audience_did, 'trusted audience key binding');
function verify(event) {
  fields(event, ['seq', 'prev_hash', 'type', 'payload', 'author_did', 'ts_ms', 'content_hash', 'sig']);
  const p = event.payload;
  fields(p, ['format', 'audience_did', 'envelope_digest', 'context_digest', 'observation_digest', 'acceptance_sequence', 'accepted_at_ms', 'previous_observation_digest', 'authority', 'commit_authority', 'executable']);
  check(p.format === 'org.nth-dao.intent-acceptance-anchor.v1', 'format');
  check(p.authority === 'none' && p.commit_authority === false && p.executable === false, 'no authority');
  check(event.author_did === vectors.expected_audience_did && p.audience_did === event.author_did, 'audience');
  check(event.type === 'intent.accepted', 'event type');
  check(['envelope_digest', 'context_digest', 'observation_digest'].every(k => isHash(p[k])), 'digest');
  check(safe(p.acceptance_sequence, 1) && safe(p.accepted_at_ms, 0), 'observation integers');
  check(p.acceptance_sequence === 1 ? p.previous_observation_digest === '' : isHash(p.previous_observation_digest), 'predecessor');
  const observation = {
    format: 'org.nth-dao.intent-acceptance-observation.v1', event_type: 'intent.accepted',
    sequence: p.acceptance_sequence, envelope_digest: p.envelope_digest,
    context_digest: p.context_digest, accepted_at_ms: p.accepted_at_ms,
    previous_audit_digest: p.previous_observation_digest,
    authority: 'none', commit_authority: false, executable: false,
  };
  check(digest(observation) === p.observation_digest, 'observation hash');
  check(safe(event.seq, 0) && safe(event.ts_ms, 1) && event.ts_ms >= p.accepted_at_ms, 'event integers');
  check(typeof event.prev_hash === 'string' && /^[0-9a-f]{64}$/.test(event.prev_hash) && event.prev_hash.length === 64, 'previous event');
  const core = Object.fromEntries(['seq', 'prev_hash', 'type', 'payload', 'author_did', 'ts_ms'].map(k => [k, event[k]]));
  check(hash(canonical(core)) === event.content_hash, 'event hash');
  check(typeof event.sig === 'string' && event.sig.length === 86, 'signature length');
  const signature = Buffer.from(event.sig, 'base64url');
  check(signature.length === 64 && signature.toString('base64url') === event.sig, 'canonical signature');
  check(ed25519.verify(signature, Buffer.from(event.content_hash, 'hex'), key, { zip215: false }), 'signature');
  return p;
}
for (const example of vectors.positive_cases) {
  const payload = verify(example.event);
  check(Buffer.from(canonical(payload)).toString('hex') === example.payload_canonical_hex, 'canonical payload');
}
for (const example of vectors.negative_cases) {
  let rejected = false;
  try { verify(example.event); } catch (error) { if (!(error instanceof InvalidAnchor)) throw error; rejected = true; }
  check(rejected, 'negative accepted: ' + example.id);
}
for (const example of vectors.raw_negative_cases) {
  let rejected = false;
  try { verify(parse(example.event_json)); } catch (error) { if (!(error instanceof InvalidAnchor)) throw error; rejected = true; }
  check(rejected, 'raw negative accepted: ' + example.id);
}
process.stdout.write(JSON.stringify({ positive: vectors.positive_cases.length, negative: vectors.negative_cases.length, raw: vectors.raw_negative_cases.length }));
