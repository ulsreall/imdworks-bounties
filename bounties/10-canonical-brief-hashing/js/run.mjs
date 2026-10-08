// Driver: computes the canonical hash plus every naive variant for a vector
// file. Usage: node js/run.mjs vectors/vectors.json
import { readFileSync } from "node:fs";
import {
  briefHash,
  canonicalJson,
  naiveCrlf,
  naiveEscapeNonAscii,
  naiveFloatReward,
  naiveNfd,
  naiveTrailingNewline,
  naiveUtf16Sort,
  hashBytes,
} from "./canonical.mjs";
import { keccak256Hex } from "./keccak256.mjs";

const path = process.argv[2];
const doc = JSON.parse(readFileSync(path, "utf8"));
const out = { keccak_selftest: {}, vectors: {}, errors: {} };

// self test against published digests for low-level string
const enc = new TextEncoder();
const selftest = [
  ["", "0xc5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470"],
  ["abc", "0x4e03657aea45a94fc7d47ba826c8d667c0d1e6e33a64a036ec44f58fa12d6c45"],
  [
    "the quick brown fox jumps over the lazy dog",
    "0x865bf05cca7ba26fb8051e8366c6d19e21cadeebe3ee6bfa462b5c72275414ec",
  ],
];
for (const [text, want] of selftest) {
  const got = keccak256Hex(enc.encode(text));
  out.keccak_selftest[text || "(empty)"] = { got, want, ok: got === want };
}

for (const v of doc.vectors) {
  try {
    const hash = briefHash(v.brief);
    out.vectors[v.name] = {
      hash,
      canonical_json: canonicalJson(v.brief),
      naive: {
        nfd: keccak256Hex(naiveNfd(v.brief)),
        crlf: keccak256Hex(naiveCrlf(v.brief)),
        trailing_newline: keccak256Hex(naiveTrailingNewline(v.brief)),
        float_reward: keccak256Hex(naiveFloatReward(v.brief)),
        escape_non_ascii: keccak256Hex(naiveEscapeNonAscii(v.brief)),
      },
      utf16_sort: naiveUtf16Sort(v.brief),
    };
  } catch (err) {
    out.errors[v.name] = String(err.message || err);
  }
}

// raw-bytes helper check: must equal the published digest for the empty file
out.raw_bytes_selftest = hashBytes(new Uint8Array(0));

process.stdout.write(JSON.stringify(out));
