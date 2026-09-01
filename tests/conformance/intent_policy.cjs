'use strict';

const fs = require('fs');
const crypto = require('crypto');

const hash = /^sha256:[0-9a-f]{64}$/;
const identifier = /^[A-Za-z0-9][A-Za-z0-9._:/-]{0,255}$/;
const base58Alphabet = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz';
const memberFields = [
  'allowed_solver_classes', 'automation_ceiling', 'role', 'signer_did', 'status',
];
const policyFields = [
  'allowed_acceptance_roles', 'audience_did', 'authority', 'commit_authority',
  'executable', 'expires_at_ms', 'format', 'issued_at_ms', 'members',
  'membership_digest', 'policy_revision', 'previous_policy_digest',
  'reviewed_draft_digest', 'revocation_digest', 'scope_id', 'version',
];

function fail(message) { throw new Error(message); }
function check(condition, message) { if (!condition) fail(message); }
function sameFields(value, fields) {
  return value && typeof value === 'object' && !Array.isArray(value)
    && Object.keys(value).sort().join('\0') === [...fields].sort().join('\0');
}
function decodeBase58(value) {
  if (!value || [...value].some(char => !base58Alphabet.includes(char))) return null;
  let number = 0n;
  for (const char of value) number = number * 58n + BigInt(base58Alphabet.indexOf(char));
  let hex = number === 0n ? '' : number.toString(16);
  if (hex.length % 2) hex = `0${hex}`;
  const body = hex ? Buffer.from(hex, 'hex') : Buffer.alloc(0);
  let zeroes = 0;
  while (zeroes < value.length && value[zeroes] === '1') zeroes += 1;
  return Buffer.concat([Buffer.alloc(zeroes), body]);
}
function encodeBase58(value) {
  let zeroes = 0;
  while (zeroes < value.length && value[zeroes] === 0) zeroes += 1;
  let number = value.length ? BigInt(`0x${value.toString('hex') || '0'}`) : 0n;
  let encoded = '';
  while (number > 0n) {
    const remainder = Number(number % 58n);
    number /= 58n;
    encoded = base58Alphabet[remainder] + encoded;
  }
  return '1'.repeat(zeroes) + encoded;
}
const ed25519Prime = (1n << 255n) - 19n;
const ed25519Order = (1n << 252n) + 27742317777372353535851937790883648493n;
function mod(value) {
  const result = value % ed25519Prime;
  return result < 0n ? result + ed25519Prime : result;
}
function modPow(base, exponent) {
  let result = 1n;
  let factor = mod(base);
  let power = exponent;
  while (power > 0n) {
    if (power & 1n) result = mod(result * factor);
    factor = mod(factor * factor);
    power >>= 1n;
  }
  return result;
}
function invert(value) { return modPow(value, ed25519Prime - 2n); }
const ed25519D = mod(-121665n * invert(121666n));
const sqrtMinusOne = modPow(2n, (ed25519Prime - 1n) / 4n);
function littleEndianInteger(bytes) {
  let value = 0n;
  for (let index = bytes.length - 1; index >= 0; index -= 1) {
    value = (value << 8n) + BigInt(bytes[index]);
  }
  return value;
}
function decodeEd25519Point(encoded) {
  const bytes = Buffer.from(encoded);
  const sign = bytes[31] >> 7;
  bytes[31] &= 0x7f;
  const y = littleEndianInteger(bytes);
  if (y >= ed25519Prime) return null;
  const ySquared = mod(y * y);
  const xSquared = mod((ySquared - 1n) * invert(ed25519D * ySquared + 1n));
  let x = modPow(xSquared, (ed25519Prime + 3n) / 8n);
  if (mod(x * x - xSquared) !== 0n) x = mod(x * sqrtMinusOne);
  if (mod(x * x - xSquared) !== 0n) return null;
  if (Number(x & 1n) !== sign) x = mod(-x);
  if (x === 0n && sign !== 0) return null;
  return { x, y, z: 1n, t: mod(x * y) };
}
function addEd25519(first, second) {
  const a = mod((first.y - first.x) * (second.y - second.x));
  const b = mod((first.y + first.x) * (second.y + second.x));
  const c = mod(2n * ed25519D * first.t * second.t);
  const d = mod(2n * first.z * second.z);
  const e = mod(b - a); const f = mod(d - c);
  const g = mod(d + c); const h = mod(b + a);
  return { x: mod(e * f), y: mod(g * h), z: mod(f * g), t: mod(e * h) };
}
function doubleEd25519(point) {
  const a = mod(point.x * point.x); const b = mod(point.y * point.y);
  const c = mod(2n * point.z * point.z); const d = mod(-a);
  const e = mod((point.x + point.y) ** 2n - a - b);
  const g = mod(d + b); const f = mod(g - c); const h = mod(d - b);
  return { x: mod(e * f), y: mod(g * h), z: mod(f * g), t: mod(e * h) };
}
function multiplyEd25519(point, scalar) {
  let result = { x: 0n, y: 1n, z: 1n, t: 0n };
  let addend = point;
  let remaining = scalar;
  while (remaining > 0n) {
    if (remaining & 1n) result = addEd25519(result, addend);
    addend = doubleEd25519(addend);
    remaining >>= 1n;
  }
  return result;
}
function primeOrderEd25519(encoded) {
  const point = decodeEd25519Point(encoded);
  if (point === null || (point.x === 0n && point.y === 1n)) return false;
  const product = multiplyEd25519(point, ed25519Order);
  return product.x === 0n && mod(product.y - product.z) === 0n;
}
function validDidKey(value) {
  if (typeof value !== 'string' || !value.startsWith('did:key:z')) return false;
  const encoded = value.slice('did:key:z'.length);
  const raw = decodeBase58(encoded);
  return raw !== null && raw.length === 34 && raw[0] === 0xed && raw[1] === 0x01
    && encodeBase58(raw) === encoded && primeOrderEd25519(raw.subarray(2));
}
function canonical(value) {
  if (value === null) return 'null';
  if (typeof value === 'boolean') return value ? 'true' : 'false';
  if (typeof value === 'number') {
    check(Number.isSafeInteger(value), 'numbers must be safe integers');
    return String(value);
  }
  if (typeof value === 'string') return JSON.stringify(value);
  if (Array.isArray(value)) return `[${value.map(canonical).join(',')}]`;
  check(value && typeof value === 'object', 'unsupported JSON value');
  return `{${Object.keys(value).sort().map(
    key => `${JSON.stringify(key)}:${canonical(value[key])}`,
  ).join(',')}}`;
}
function digest(value) {
  return `sha256:${crypto.createHash('sha256').update(canonical(value)).digest('hex')}`;
}
function sortedUnique(values) {
  return values.length > 0 && values.join('\0') === [...new Set(values)].sort().join('\0');
}
function validateMember(member) {
  check(sameFields(member, memberFields), 'member fields');
  check(validDidKey(member.signer_did), 'member DID');
  check(['owner', 'admin', 'member'].includes(member.role), 'member role');
  check(['active', 'revoked'].includes(member.status), 'member status');
  check(Array.isArray(member.allowed_solver_classes)
    && member.allowed_solver_classes.length <= 16
    && sortedUnique(member.allowed_solver_classes)
    && member.allowed_solver_classes.every(value => identifier.test(value)), 'solver classes');
  check(['A0', 'A1'].includes(member.automation_ceiling), 'automation ceiling');
}
function validatePolicy(policy) {
  check(sameFields(policy, policyFields), 'policy fields');
  check(policy.format === 'org.nth-dao.intent-acceptance-policy-snapshot'
    && policy.version === '1', 'policy profile');
  check(policy.authority === 'intent-draft-acceptance'
    && policy.commit_authority === false && policy.executable === false, 'authority boundary');
  check(validDidKey(policy.audience_did) && identifier.test(policy.scope_id), 'policy key');
  for (const field of ['reviewed_draft_digest', 'membership_digest', 'revocation_digest']) {
    check(hash.test(policy[field]), `${field} hash`);
  }
  check(Number.isSafeInteger(policy.policy_revision) && policy.policy_revision >= 1, 'revision');
  check(policy.policy_revision === 1 ? policy.previous_policy_digest === ''
    : hash.test(policy.previous_policy_digest), 'predecessor');
  check(Number.isSafeInteger(policy.issued_at_ms) && Number.isSafeInteger(policy.expires_at_ms)
    && policy.issued_at_ms >= 0 && policy.issued_at_ms < policy.expires_at_ms
    && policy.expires_at_ms - policy.issued_at_ms <= 2678400000, 'validity');
  check(Array.isArray(policy.allowed_acceptance_roles)
    && policy.allowed_acceptance_roles.length <= 3
    && sortedUnique(policy.allowed_acceptance_roles)
    && policy.allowed_acceptance_roles.every(role => ['owner', 'admin', 'member'].includes(role)), 'roles');
  check(Array.isArray(policy.members) && policy.members.length >= 1 && policy.members.length <= 64, 'members');
  policy.members.forEach(validateMember);
  check(sortedUnique(policy.members.map(member => member.signer_did)), 'member ordering');
  check(Buffer.byteLength(canonical(policy)) <= 524288, 'document limit');
}
function resolve(policy, request) {
  validatePolicy(policy);
  check(policy.issued_at_ms <= request.now_ms && request.now_ms < policy.expires_at_ms, 'policy expired');
  const member = policy.members.find(item => item.signer_did === request.signer_did);
  check(member && member.status === 'active', 'member denied');
  check(policy.allowed_acceptance_roles.includes(member.role), 'role denied');
  return {
    signer_did: member.signer_did,
    audience_did: policy.audience_did,
    scope_id: policy.scope_id,
    draft_digest: policy.reviewed_draft_digest,
    revision: request.head.revision + 1,
    previous_digest: request.head.digest,
    allowed_solver_classes: member.allowed_solver_classes,
    automation_ceiling: member.automation_ceiling,
    authorization_digest: digest(policy),
  };
}
function verifySuccessor(previous, successor) {
  validatePolicy(previous); validatePolicy(successor);
  check(successor.audience_did === previous.audience_did && successor.scope_id === previous.scope_id, 'scope');
  check(successor.policy_revision === previous.policy_revision + 1, 'revision continuity');
  check(successor.previous_policy_digest === digest(previous), 'predecessor binding');
  check(successor.issued_at_ms >= previous.issued_at_ms, 'successor time');
  const revoked = new Set(previous.members.filter(member => member.status === 'revoked').map(member => member.signer_did));
  const stillRevoked = new Set(successor.members.filter(member => member.status === 'revoked').map(member => member.signer_did));
  check([...revoked].every(did => stillRevoked.has(did)), 'revocation monotonicity');
}

const vectors = JSON.parse(fs.readFileSync(process.argv[2], 'utf8'));
let positive = 0; let negative = 0; let successors = 0;
for (const item of vectors.positive_cases) {
  validatePolicy(item.policy);
  check(Buffer.from(canonical(item.policy)).toString('hex') === item.canonical_hex, `${item.id} canonical`);
  check(digest(item.policy) === item.digest, `${item.id} digest`);
  if (item.resolution) {
    check(canonical(resolve(item.policy, item.resolution)) === canonical(item.resolution.expected), `${item.id} resolution`);
  }
  positive += 1;
}
for (const item of vectors.negative_cases) {
  try { validatePolicy(item.policy); fail(`${item.id} unexpectedly valid`); }
  catch (error) { if (error.message.endsWith('unexpectedly valid')) throw error; }
  negative += 1;
}
for (const item of vectors.successor_cases) {
  let valid = true;
  try { verifySuccessor(item.previous, item.successor); } catch (_error) { valid = false; }
  check(valid === item.valid, `${item.id} successor result`);
  successors += 1;
}
process.stdout.write(JSON.stringify({ positive, negative, successors }));
