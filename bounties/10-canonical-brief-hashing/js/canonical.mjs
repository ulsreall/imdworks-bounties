// Canonical brief form and hashing (JavaScript implementation).
//
// Written independently from the Python implementation for the same bounty:
// same published spec (CANONICAL BRIEF FORM v1, see py/canonical.py), separate
// code, separate JSON serialiser, separate string escaping. The two are
// compared vector by vector in scripts/run.py.

import { keccak256, toHex } from "./keccak256.mjs";

const REQUIRED_FIELDS = ["title", "description", "criteria", "reward", "currency", "deadline", "repo_url"];
const OPTIONAL_FIELDS = ["meta"];
const ALLOWED_FIELDS = new Set([...REQUIRED_FIELDS, ...OPTIONAL_FIELDS]);
const CURRENCIES = new Set(["USDG", "USDC"]);
const AMOUNT_RE = /^(0|[1-9][0-9]*)(\.[0-9]{1,6})?$/;
const DEADLINE_RE = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$/;
const URL_RE = /^https?:\/\/[^\s]+$/;
const CONTROL_RE = /[\u0000-\u0008\u000b\u000c\u000e-\u001f]/g;

export class BriefError extends Error {}

export function normalizeText(value, what) {
  if (typeof value !== "string") throw new BriefError(`${what} must be a string`);
  let text = value.replace(/\r\n/g, "\n").replace(/\r/g, "\n");
  text = text.normalize("NFC");
  text = text.replace(CONTROL_RE, "");
  return text;
}

export function validate(brief) {
  if (typeof brief !== "object" || brief === null || Array.isArray(brief)) {
    throw new BriefError("brief must be an object");
  }
  const keys = Object.keys(brief);
  const unknown = keys.filter((k) => !ALLOWED_FIELDS.has(k));
  if (unknown.length) throw new BriefError(`unknown fields are not canonical: ${unknown.join(",")}`);
  const missing = REQUIRED_FIELDS.filter((f) => !(f in brief));
  if (missing.length) throw new BriefError(`missing required fields: ${missing.join(",")}`);

  const out = {
    title: normalizeText(brief.title, "title"),
    description: normalizeText(brief.description, "description"),
    criteria: normalizeText(brief.criteria, "criteria"),
    reward: brief.reward,
    currency: brief.currency,
    deadline: brief.deadline,
    repo_url: brief.repo_url,
  };
  if (out.title.length < 1 || out.title.length > 200) throw new BriefError("title length out of range");
  if (out.description.length > 20000 || out.criteria.length > 20000) throw new BriefError("description/criteria too long");
  if (typeof out.reward !== "string" || !AMOUNT_RE.test(out.reward)) throw new BriefError("reward must be a canonical decimal string");
  {
    const [whole, frac = ""] = out.reward.split(".");
    const micros = BigInt(whole) * 1000000n + BigInt(frac.padEnd(6, "0") || "0");
    if (micros > (1n << 256n) - 1n) throw new BriefError("reward exceeds uint256 micro-units");
  }
  if (!CURRENCIES.has(out.currency)) throw new BriefError("unsupported currency");
  if (typeof out.deadline !== "string" || !DEADLINE_RE.test(out.deadline)) throw new BriefError("deadline must be RFC3339 UTC ending in Z");
  if (out.repo_url !== null) {
    if (typeof out.repo_url !== "string" || !URL_RE.test(out.repo_url)) throw new BriefError("repo_url must be http(s) or null");
  }
  if ("meta" in brief) {
    const meta = brief.meta;
    if (typeof meta !== "object" || meta === null || Array.isArray(meta)) throw new BriefError("meta must be an object");
    const clean = {};
    for (const [k, v] of Object.entries(meta)) {
      if (typeof v !== "string") throw new BriefError("meta values must be strings");
      clean[normalizeText(k, "meta key")] = normalizeText(v, "meta value");
    }
    if (Object.keys(clean).length) out.meta = clean;
  }
  return out;
}

/** Compare by Unicode code point. Array#sort() would compare UTF-16 units. */
export function compareCodePoint(a, b) {
  const A = Array.from(a);
  const B = Array.from(b);
  const n = Math.min(A.length, B.length);
  for (let i = 0; i < n; i++) {
    const ca = A[i].codePointAt(0);
    const cb = B[i].codePointAt(0);
    if (ca !== cb) return ca < cb ? -1 : 1;
  }
  return A.length === B.length ? 0 : A.length < B.length ? -1 : 1;
}

// Mirrors the Python escaper: only ", \, \n, \t and other C0 controls are
// escaped. Everything else (including U+2028 and emoji) is emitted raw.
export function escapeString(text) {
  let out = '"';
  for (const ch of text) {
    const code = ch.codePointAt(0);
    if (ch === '"') out += '\\"';
    else if (ch === "\\") out += "\\\\";
    else if (ch === "\n") out += "\\n";
    else if (ch === "\t") out += "\\t";
    else if (code < 0x20) out += "\\u" + code.toString(16).padStart(4, "0");
    else out += ch;
  }
  return out + '"';
}

export function serialize(value) {
  if (typeof value === "string") return escapeString(value);
  if (value === null) return "null";
  if (typeof value === "boolean") return value ? "true" : "false";
  if (Array.isArray(value)) return "[" + value.map(serialize).join(",") + "]";
  if (typeof value === "object") {
    const keys = Object.keys(value).sort(compareCodePoint);
    return "{" + keys.map((k) => escapeString(k) + ":" + serialize(value[k])).join(",") + "}";
  }
  throw new BriefError(`unsupported value type in canonical form: ${typeof value}`);
}

export function canonicalJson(brief) {
  return serialize(validate(brief));
}

export function canonicalBytes(brief) {
  return new TextEncoder().encode(canonicalJson(brief));
}

export function briefHash(brief) {
  return toHex(keccak256(canonicalBytes(brief)));
}

/** keccak256 over arbitrary bytes, for hashing published brief files verbatim. */
export function hashBytes(bytes) {
  return toHex(keccak256(bytes));
}

// --------------------------------------------------------------------------
// Naive variants: real mistakes that change the hash for at least one vector.
// --------------------------------------------------------------------------

/** Trap: Array#sort() default order is UTF-16 code units, not code points. */
export function naiveUtf16Sort(brief) {
  const fixed = validate(brief);
  const seen = new Set();
  for (const k of Object.keys(fixed)) seen.add(k);
  for (const k of Object.keys(fixed.meta || {})) seen.add(k);
  const utf16 = [...seen].sort();
  const cp = [...seen].sort(compareCodePoint);
  const differs = utf16.join("\u0001") !== cp.join("\u0001");
  return { utf16Order: utf16, codePointOrder: cp, differs };
}

/** Trap: escaping every non-ASCII character as \uXXXX for "safety". */
export function naiveEscapeNonAscii(brief) {
  const json = canonicalJson(brief);
  const escaped = json.replace(/[^\x20-\x7e]/g, (c) => {
    const cp = c.codePointAt(0);
    if (cp > 0xffff) {
      const offset = cp - 0x10000;
      const hi = 0xd800 + (offset >> 10);
      const lo = 0xdc00 + (offset & 0x3ff);
      return "\\u" + hi.toString(16).padStart(4, "0") + "\\u" + lo.toString(16).padStart(4, "0");
    }
    return "\\u" + cp.toString(16).padStart(4, "0");
  });
  return new TextEncoder().encode(escaped);
}

/** Trap: wrong Unicode normalisation form (NFD instead of NFC). */
export function naiveNfd(brief) {
  return new TextEncoder().encode(canonicalJson(brief).normalize("NFD"));
}

/** Trap: hashing a brief whose text an editor saved with CRLF endings. */
export function naiveCrlf(brief) {
  const fixed = validate(brief);
  for (const field of ["title", "description", "criteria"]) {
    if (typeof fixed[field] === "string") fixed[field] = fixed[field].replace(/\n/g, "\r\n");
  }
  return new TextEncoder().encode(serialize(fixed));
}

/** Trap: hashing a file that ends with a newline. */
export function naiveTrailingNewline(brief) {
  const bytes = canonicalBytes(brief);
  const out = new Uint8Array(bytes.length + 1);
  out.set(bytes, 0);
  out[bytes.length] = 0x0a;
  return out;
}

/** Trap: letting a float reward into the serialised bytes. */
export function naiveFloatReward(brief) {
  const fixed = validate(brief);
  const json = canonicalJson(fixed).replace(
    escapeString(fixed.reward),
    JSON.stringify(Number(fixed.reward)),
  );
  return new TextEncoder().encode(json);
}
