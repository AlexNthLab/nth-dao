// Independent Node consumer of the bounded v1 envelope profile, not a runtime SDK.
const fs = require('node:fs');
const crypto = require('node:crypto');
const { ed25519 } = require('@noble/curves/ed25519.js');
class ValidationError extends Error {}
function check(ok, message) { if (!ok) throw new ValidationError(message); }
// Never fall back to Number-only validation after JSON has erased token syntax.
if (JSON.parse('0', (_key, _value, context) => context?.source) !== '0') {
  throw new Error('Conformance requires native JSON.parse source context (Node >=22.13)');
}
function parseWireJSON(raw) {
  try {
    return JSON.parse(raw, (_key, value, context) => {
      if (typeof value === 'number') {
        check(/^-?(?:0|[1-9][0-9]*)$/.test(context.source), 'JSON number must use an integer token');
      }
      return value;
    });
  } catch (error) {
    if (error instanceof SyntaxError) throw new ValidationError('invalid JSON syntax');
    throw error;
  }
}
const input = parseWireJSON(fs.readFileSync(0, 'utf8'));
const { vectors, schema, draftSchema } = input;
const id = /^[A-Za-z0-9][A-Za-z0-9._:/-]{0,255}$/;
const hash = /^sha256:[0-9a-f]{64}$/;
const domain = Buffer.from('NTH-DAO:IntentEnvelope:v1\0', 'utf8');
const expectedFields = ['signer_did', 'audience_did', 'scope_id', 'draft_digest', 'revision', 'previous_digest', 'automation_ceiling'];
const expectedSchema = {
  type: 'object', additionalProperties: false,
  properties: {
    ...Object.fromEntries(expectedFields.map(key => [key, schema.properties[key]])),
    allowed_solver_classes: schema.properties.solver_classes,
  },
  required: [...expectedFields, 'allowed_solver_classes'],
};
function canonical(v) {
  if (Array.isArray(v)) return '[' + v.map(canonical).join(',') + ']';
  if (v && typeof v === 'object') return '{' + Object.keys(v).sort().map(k => JSON.stringify(k) + ':' + canonical(v[k])).join(',') + '}';
  return JSON.stringify(v);
}
function digest(v) { return 'sha256:' + crypto.createHash('sha256').update(v).digest('hex'); }
function bytes(body) { return Buffer.concat([domain, Buffer.from(canonical(body))]); }
function primeOrderPoint(encoded) {
  // Use the library's boolean decoding API so only malformed point encodings
  // become validation errors; unexpected errors below still fail the harness.
  check(ed25519.utils.isValidPublicKey(encoded, false), 'invalid Ed25519 point encoding');
  const point = ed25519.Point.fromBytes(encoded, false);
  check(!point.isSmallOrder() && point.isTorsionFree(), 'Ed25519 prime-order point');
  check(Buffer.from(point.toBytes()).equals(encoded), 'canonical Ed25519 point');
}
function integer(v, min = 0) { check(Number.isSafeInteger(v) && v >= min, 'integer'); }
function unique(items) { check(canonical(items) === canonical([...new Set(items)].sort()), 'sorted unique'); }
function validateSchema(s) {
  const allowed = ['type', 'additionalProperties', 'properties', 'required', 'items', 'enum', 'minimum', 'maximum', 'minLength', 'maxLength', 'minItems', 'maxItems'];
  check(Object.keys(s).every(k => allowed.includes(k)), 'unsupported schema keyword');
  check(['object', 'array', 'string', 'boolean', 'integer'].includes(s.type), 'unsupported schema type');
  if (s.type === 'object') {
    check(s.additionalProperties === false && s.properties && Array.isArray(s.required), 'closed object schema');
    check(s.required.every(k => Object.hasOwn(s.properties, k)), 'undeclared required field');
    Object.values(s.properties).forEach(validateSchema);
  }
  if (s.type === 'array') validateSchema(s.items);
}
function validate(v, s) {
  if (s.type === 'object') {
    check(v !== null && typeof v === 'object' && !Array.isArray(v), 'object');
    check(Object.keys(v).every(k => Object.hasOwn(s.properties, k)), 'unknown field');
    check(s.required.every(k => Object.hasOwn(v, k)), 'missing field');
    for (const k of Object.keys(v)) validate(v[k], s.properties[k]);
  } else if (s.type === 'array') {
    check(Array.isArray(v), 'array');
    check(v.length >= (s.minItems ?? 0) && v.length <= (s.maxItems ?? Infinity), 'array size');
    v.forEach(x => validate(x, s.items));
  } else if (s.type === 'integer') {
    integer(v, s.minimum ?? 0); check(v <= (s.maximum ?? Number.MAX_SAFE_INTEGER), 'maximum');
  } else {
    check(typeof v === s.type, 'scalar type');
    if (s.type === 'string') check([...v].length >= (s.minLength ?? 0) && [...v].length <= (s.maxLength ?? Infinity), 'string size');
  }
  if (s.enum) check(s.enum.includes(v), 'enum');
}
const alphabet = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz';
function didKey(did) {
  check(typeof did === 'string' && did.length <= 128 && did.startsWith('did:key:z'), 'did');
  let n = 0n;
  for (const c of did.slice(9)) { const i = alphabet.indexOf(c); check(i >= 0, 'base58'); n = n * 58n + BigInt(i); }
  let hex = n.toString(16); if (hex.length % 2) hex = '0' + hex;
  const raw = Buffer.from(hex, 'hex');
  check(raw.length === 34 && raw[0] === 0xed && raw[1] === 1, 'Ed25519');
  check(encodeDid(raw.subarray(2)) === did, 'canonical DID');
  return raw.subarray(2);
}
function encodeDid(pub) {
  let n = BigInt('0x' + Buffer.concat([Buffer.from([0xed, 1]), pub]).toString('hex')), out = '';
  while (n) { out = alphabet[Number(n % 58n)] + out; n /= 58n; }
  return 'did:key:z' + out;
}
function text(value, max = 8192, multiline = false, empty = false) {
  check(typeof value === 'string' && Buffer.byteLength(value) <= max, 'text size');
  check(empty || value.replace(/[\u0009-\u000d\u001c-\u0020\u0085\u00a0\u1680\u2000-\u200a\u2028\u2029\u202f\u205f\u3000]/g, '').length > 0, 'blank text');
  check(![...value].some(c => {
    const n = c.codePointAt(0);
    return (n < 32 || n === 127) && !(multiline && '\n\r\t'.includes(c));
  }), 'control text');
  check(!/[\ud800-\udfff]/u.test(value), 'surrogate');
}
function draft(raw) {
  check(Buffer.byteLength(raw) <= 131072, 'draft size');
  const d = parseWireJSON(raw);
  validate(d, draftSchema);
  check(canonical(d) === raw, 'draft canonical');
  check(d.authority === 'none' && d.commit_authority === false && d.executable === false && d.review_required === true, 'draft authority');
  check(id.test(d.request_id) && hash.test(d.request_digest), 'draft identifiers');
  check(/^[A-Za-z]{2,8}(?:-[A-Za-z0-9]{1,8}){0,3}$/.test(d.locale), 'locale');
  text(d.source_text, 32768, true); text(d.summary, 8192, true);
  for (const key of ['outcomes', 'assumptions', 'constraints', 'risks']) d[key].forEach(x => text(x, 8192, true));
  unique(d.requested_capabilities); check(d.requested_capabilities.every(x => id.test(x)), 'capability ID');
  check(d.clarifications.length === 0 && d.outcomes.length > 0, 'unreviewed draft');
  const digests = [];
  for (const a of d.attachments) {
    check(hash.test(a.digest) && a.verification_status === 'unverified', 'attachment claim');
    check(/^[A-Za-z0-9][A-Za-z0-9!#$&^_.+-]{0,126}\/[A-Za-z0-9][A-Za-z0-9!#$&^_.+-]{0,126}$/.test(a.media_type), 'media type');
    text(a.name, 8192, false, true); integer(a.size_bytes); digests.push(a.digest);
  }
  check(new Set(digests).size === digests.length, 'duplicate attachments');
  const req = { operation: 'resolve' };
  for (const k of ['attachments', 'automation_ceiling', 'locale', 'request_id', 'source_kind', 'source_text']) req[k] = d[k];
  check(digest(canonical(req)) === d.request_digest, 'source binding');
  return d;
}
function validateExpectedContext(expected) {
  validate(expected, expectedSchema);
  didKey(expected.signer_did); didKey(expected.audience_did);
  check(id.test(expected.scope_id) && hash.test(expected.draft_digest), 'expected identifiers');
  check(expected.revision === 1 ? expected.previous_digest === '' : hash.test(expected.previous_digest), 'expected lineage');
  unique(expected.allowed_solver_classes);
  check(expected.allowed_solver_classes.every(x => id.test(x)), 'expected solver classes');
}
function verifyCase(c) {
  const e = c.envelope, expected = c.expected;
  validateExpectedContext(expected);
  validate(e, schema); check(Buffer.byteLength(canonical(e)) <= 262144, 'envelope size');
  didKey(e.signer_did); didKey(e.audience_did);
  check(id.test(e.scope_id), 'scope'); unique(e.solver_classes);
  check(e.solver_classes.every(x => id.test(x)), 'solver class');
  check(/^[0-9a-f]{32}$/.test(e.nonce), 'nonce');
  check(e.expires_at_ms > e.issued_at_ms && e.expires_at_ms - e.issued_at_ms <= 86400000, 'TTL');
  check(e.revision === 1 ? e.previous_digest === '' : hash.test(e.previous_digest), 'lineage');
  const d = draft(e.draft_json);
  check(digest(e.draft_json) === e.draft_digest, 'draft digest');
  check(['A0','A1'].indexOf(e.automation_ceiling) <= ['A0','A1','A2','A3','A4'].indexOf(d.automation_ceiling), 'draft ceiling');
  check(/^[0-9a-f]{128}$/.test(e.signature), 'signature encoding');
  const { signature, ...body } = e;
  const publicKey = didKey(e.signer_did), signatureBytes = Buffer.from(signature, 'hex');
  primeOrderPoint(publicKey); primeOrderPoint(signatureBytes.subarray(0, 32));
  check(ed25519.verify(signatureBytes, bytes(body), publicKey, { zip215: false }), 'signature');
  for (const f of ['signer_did','audience_did','scope_id','draft_digest','revision','previous_digest']) check(e[f] === expected[f], 'expected ' + f);
  integer(c.now_ms); check(e.issued_at_ms <= c.now_ms && c.now_ms < e.expires_at_ms, 'clock');
  const allowedSolvers = new Set(expected.allowed_solver_classes);
  check(e.solver_classes.every(x => allowedSolvers.has(x)), 'Host solver policy');
  check(['A0','A1'].indexOf(e.automation_ceiling) <= ['A0','A1'].indexOf(expected.automation_ceiling), 'Host ceiling');
  return body;
}
validateSchema(schema); validateSchema(draftSchema); validateSchema(expectedSchema);
check(domain.toString('hex') === vectors.signing_domain_hex, 'domain');
for (const c of vectors.positive_cases) {
  const body = verifyCase(c);
  check(bytes(body).toString('hex') === c.signing_bytes_hex, 'signing bytes');
  check(digest(canonical(c.envelope)) === c.document_digest, 'document digest');
}
for (const c of input.negative_cases) {
  let rejected = false;
  try { verifyCase(c); } catch (error) {
    if (!(error instanceof ValidationError)) throw error;
    rejected = true;
  }
  check(rejected, 'negative accepted: ' + c.id);
}
for (const c of vectors.raw_json_cases) {
  let accepted = false;
  try { verifyCase(parseWireJSON(c.case_json)); accepted = true; } catch (error) {
    if (!(error instanceof ValidationError)) throw error;
  }
  check(accepted === c.accept, 'raw JSON result mismatch: ' + c.id);
}
// Sign with a new ephemeral Node-generated key; Python must verify this result.
const pair = crypto.generateKeyPairSync('ed25519');
const body = { ...vectors.positive_cases[0].envelope };
delete body.signature;
body.signer_did = encodeDid(pair.publicKey.export({format:'der',type:'spki'}).subarray(-32));
const signature = crypto.sign(null, bytes(body), pair.privateKey).toString('hex');
process.stdout.write(JSON.stringify({ positive: vectors.positive_cases.length, negative: input.negative_cases.length, raw_json: vectors.raw_json_cases.length, envelope: {...body, signature} }));
