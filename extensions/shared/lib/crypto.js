//! AuraPass bridge cryptography for browser extensions.
//!
//! Everything here is dependency-free ES module code that runs in a MV3
//! service worker, a content script or plain Node. SHA-256, HMAC-SHA256 and
//! HKDF come from WebCrypto; ChaCha20, Poly1305 and their XChaCha20-Poly1305
//! AEAD combination are implemented here because browsers do not expose them.
//!
//! The implementation follows RFC 8439 (ChaCha20 & Poly1305) and
//! draft-irtf-cfrg-xchacha-03 (XChaCha20), and is checked against the published
//! test vectors in `extensions/tools/test-crypto.mjs`.

const SIGMA = [0x61707865, 0x3320646e, 0x79622d32, 0x6b206574];

/** Protocol version; must match `aurapass_core::ipc::PROTOCOL_VERSION`. */
export const PROTOCOL_VERSION = 1;

const HELLO_CONTEXT = new TextEncoder().encode("aurapass/v2/bridge-hello");
const SESSION_INFO = new TextEncoder().encode("aurapass/v2/bridge-session");

// ----------------------------------------------------------------- low level

function rotl(v, n) {
  return ((v << n) | (v >>> (32 - n))) >>> 0;
}

function quarterRound(x, a, b, c, d) {
  x[a] = (x[a] + x[b]) >>> 0;
  x[d] = rotl(x[d] ^ x[a], 16);
  x[c] = (x[c] + x[d]) >>> 0;
  x[b] = rotl(x[b] ^ x[c], 12);
  x[a] = (x[a] + x[b]) >>> 0;
  x[d] = rotl(x[d] ^ x[a], 8);
  x[c] = (x[c] + x[d]) >>> 0;
  x[b] = rotl(x[b] ^ x[c], 7);
}

function leWords(bytes, count) {
  const out = new Array(count);
  for (let i = 0; i < count; i++) {
    const o = i * 4;
    out[i] = (bytes[o] | (bytes[o + 1] << 8) | (bytes[o + 2] << 16) | (bytes[o + 3] << 24)) >>> 0;
  }
  return out;
}

function wordsToBytes(words) {
  const out = new Uint8Array(words.length * 4);
  for (let i = 0; i < words.length; i++) {
    const w = words[i];
    out[i * 4] = w & 0xff;
    out[i * 4 + 1] = (w >>> 8) & 0xff;
    out[i * 4 + 2] = (w >>> 16) & 0xff;
    out[i * 4 + 3] = (w >>> 24) & 0xff;
  }
  return out;
}

/** One 64-byte ChaCha20 keystream block. */
function chacha20Block(key, counter, nonce12) {
  const state = new Uint32Array(16);
  state[0] = SIGMA[0];
  state[1] = SIGMA[1];
  state[2] = SIGMA[2];
  state[3] = SIGMA[3];
  const k = leWords(key, 8);
  for (let i = 0; i < 8; i++) state[4 + i] = k[i];
  state[12] = counter >>> 0;
  const n = leWords(nonce12, 3);
  state[13] = n[0];
  state[14] = n[1];
  state[15] = n[2];

  const x = state.slice();
  for (let i = 0; i < 10; i++) {
    quarterRound(x, 0, 4, 8, 12);
    quarterRound(x, 1, 5, 9, 13);
    quarterRound(x, 2, 6, 10, 14);
    quarterRound(x, 3, 7, 11, 15);
    quarterRound(x, 0, 5, 10, 15);
    quarterRound(x, 1, 6, 11, 12);
    quarterRound(x, 2, 7, 8, 13);
    quarterRound(x, 3, 4, 9, 14);
  }
  const out = new Array(16);
  for (let i = 0; i < 16; i++) out[i] = (x[i] + state[i]) >>> 0;
  return wordsToBytes(out);
}

/** HChaCha20: derive a 32-byte sub-key from a key and 16-byte nonce. */
export function hchacha20(key, nonce16) {
  const state = new Uint32Array(16);
  state[0] = SIGMA[0];
  state[1] = SIGMA[1];
  state[2] = SIGMA[2];
  state[3] = SIGMA[3];
  const k = leWords(key, 8);
  for (let i = 0; i < 8; i++) state[4 + i] = k[i];
  const n = leWords(nonce16, 4);
  state[12] = n[0];
  state[13] = n[1];
  state[14] = n[2];
  state[15] = n[3];

  const x = state.slice();
  for (let i = 0; i < 10; i++) {
    quarterRound(x, 0, 4, 8, 12);
    quarterRound(x, 1, 5, 9, 13);
    quarterRound(x, 2, 6, 10, 14);
    quarterRound(x, 3, 7, 11, 15);
    quarterRound(x, 0, 5, 10, 15);
    quarterRound(x, 1, 6, 11, 12);
    quarterRound(x, 2, 7, 8, 13);
    quarterRound(x, 3, 4, 9, 14);
  }
  const picked = [x[0], x[1], x[2], x[3], x[12], x[13], x[14], x[15]];
  return wordsToBytes(picked);
}

/** XOR `data` with the ChaCha20 keystream, starting at `counter`. */
function chacha20Xor(key, counter, nonce12, data) {
  const out = new Uint8Array(data.length);
  let offset = 0;
  let blockCounter = counter >>> 0;
  while (offset < data.length) {
    const block = chacha20Block(key, blockCounter, nonce12);
    const take = Math.min(64, data.length - offset);
    for (let i = 0; i < take; i++) out[offset + i] = data[offset + i] ^ block[i];
    offset += take;
    blockCounter = (blockCounter + 1) >>> 0;
  }
  return out;
}

function leToBigInt(bytes) {
  let value = 0n;
  for (let i = bytes.length - 1; i >= 0; i--) {
    value = (value << 8n) | BigInt(bytes[i]);
  }
  return value;
}

function bigIntToLe16(value) {
  const out = new Uint8Array(16);
  let v = value;
  for (let i = 0; i < 16; i++) {
    out[i] = Number(v & 0xffn);
    v >>= 8n;
  }
  return out;
}

const P1305 = (1n << 130n) - 5n;
const CLAMP = 0x0ffffffc0ffffffc0ffffffc0fffffffn;

/** Poly1305 one-time authenticator (RFC 8439 §2.5). */
export function poly1305(key32, message) {
  const r = leToBigInt(key32.subarray(0, 16)) & CLAMP;
  const s = leToBigInt(key32.subarray(16, 32));
  let acc = 0n;
  for (let i = 0; i < message.length; i += 16) {
    const chunk = message.subarray(i, Math.min(i + 16, message.length));
    let n = leToBigInt(chunk);
    n += 1n << BigInt(8 * chunk.length);
    acc = ((acc + n) * r) % P1305;
  }
  acc = (acc + s) & ((1n << 128n) - 1n);
  return bigIntToLe16(acc);
}

function pad16(length) {
  const rem = length % 16;
  return rem === 0 ? new Uint8Array(0) : new Uint8Array(16 - rem);
}

function concat(...parts) {
  let total = 0;
  for (const p of parts) total += p.length;
  const out = new Uint8Array(total);
  let offset = 0;
  for (const p of parts) {
    out.set(p, offset);
    offset += p.length;
  }
  return out;
}

function le64(value) {
  const out = new Uint8Array(8);
  let v = BigInt(value);
  for (let i = 0; i < 8; i++) {
    out[i] = Number(v & 0xffn);
    v >>= 8n;
  }
  return out;
}

function polyInput(aad, ciphertext) {
  return concat(aad, pad16(aad.length), ciphertext, pad16(ciphertext.length), le64(aad.length), le64(ciphertext.length));
}

// --------------------------------------------------------- the AEAD proper

/** XChaCha20-Poly1305 seal. Returns `ciphertext || tag`. */
export function xchachaSeal(key, nonce24, aad, plaintext) {
  const subkey = hchacha20(key, nonce24.subarray(0, 16));
  const nonce12 = new Uint8Array(12);
  nonce12.set(nonce24.subarray(16, 24), 4);

  const polyKey = chacha20Block(subkey, 0, nonce12).subarray(0, 32);
  const ciphertext = chacha20Xor(subkey, 1, nonce12, plaintext);
  const tag = poly1305(polyKey, polyInput(aad, ciphertext));
  return concat(ciphertext, tag);
}

/** XChaCha20-Poly1305 open. Returns `null` when the tag does not verify. */
export function xchachaOpen(key, nonce24, aad, sealed) {
  if (sealed.length < 16) return null;
  const subkey = hchacha20(key, nonce24.subarray(0, 16));
  const nonce12 = new Uint8Array(12);
  nonce12.set(nonce24.subarray(16, 24), 4);

  const ciphertext = sealed.subarray(0, sealed.length - 16);
  const tag = sealed.subarray(sealed.length - 16);
  const polyKey = chacha20Block(subkey, 0, nonce12).subarray(0, 32);
  const expected = poly1305(polyKey, polyInput(aad, ciphertext));
  if (!constantTimeEqual(expected, tag)) return null;
  return chacha20Xor(subkey, 1, nonce12, ciphertext);
}

function constantTimeEqual(a, b) {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) diff |= a[i] ^ b[i];
  return diff === 0;
}

// ------------------------------------------------------------- bridge crypto

const encoder = new TextEncoder();
const decoder = new TextDecoder();

/** SHA-256, as bytes. */
export async function sha256(bytes) {
  return new Uint8Array(await crypto.subtle.digest("SHA-256", bytes));
}

function be32(value) {
  return new Uint8Array([(value >>> 24) & 0xff, (value >>> 16) & 0xff, (value >>> 8) & 0xff, value & 0xff]);
}

/** `HMAC-SHA256(SHA-256(token), context ‖ salt ‖ protocol)`, base64url. */
export async function helloProof(token, salt, protocol = PROTOCOL_VERSION) {
  const keyBytes = await sha256(encoder.encode(token));
  const key = await crypto.subtle.importKey("raw", keyBytes, { name: "HMAC", hash: "SHA-256" }, false, ["sign"]);
  const message = concat(HELLO_CONTEXT, salt, be32(protocol));
  const signature = new Uint8Array(await crypto.subtle.sign("HMAC", key, message));
  return b64urlEncode(signature);
}

/** HKDF-SHA256 session key, matching `aurapass_core::ipc::session_key`. */
export async function sessionKey(token, salt) {
  const base = await sha256(encoder.encode(token));
  const key = await crypto.subtle.importKey("raw", base, "HKDF", false, ["deriveBits"]);
  const bits = await crypto.subtle.deriveBits(
    { name: "HKDF", hash: "SHA-256", salt, info: SESSION_INFO },
    key,
    256,
  );
  return new Uint8Array(bits);
}

/** Seal a JSON message into a bridge frame (`b64(nonce).b64(ct)`). */
export function sealFrame(key, message) {
  const plaintext = encoder.encode(JSON.stringify(message));
  const nonce = randomBytes(24);
  const sealed = xchachaSeal(key, nonce, be32(PROTOCOL_VERSION), plaintext);
  return `${b64Encode(nonce)}.${b64Encode(sealed)}`;
}

/** Open a bridge frame back into a JSON value. Throws on tampering. */
export function openFrame(key, frame) {
  const dot = frame.indexOf(".");
  if (dot < 0) throw new Error("malformed bridge frame");
  const nonce = b64Decode(frame.slice(0, dot));
  const sealed = b64Decode(frame.slice(dot + 1));
  const plaintext = xchachaOpen(key, nonce, be32(PROTOCOL_VERSION), sealed);
  if (plaintext === null) throw new Error("bridge frame failed authentication");
  return JSON.parse(decoder.decode(plaintext));
}

// ------------------------------------------------------------------ base64

export function randomBytes(length) {
  const out = new Uint8Array(length);
  crypto.getRandomValues(out);
  return out;
}

export function b64Encode(bytes) {
  let binary = "";
  for (const b of bytes) binary += String.fromCharCode(b);
  return btoa(binary);
}

export function b64Decode(text) {
  const binary = atob(text.trim());
  const out = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) out[i] = binary.charCodeAt(i);
  return out;
}

export function b64urlEncode(bytes) {
  return b64Encode(bytes).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

export function b64urlDecode(text) {
  const padded = text.replace(/-/g, "+").replace(/_/g, "/");
  const pad = padded.length % 4 === 0 ? "" : "=".repeat(4 - (padded.length % 4));
  return b64Decode(padded + pad);
}

export { concat };
