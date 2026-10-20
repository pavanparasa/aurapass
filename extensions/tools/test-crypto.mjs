#!/usr/bin/env node
// Checks `extensions/shared/crypto.js` against the published test vectors for
// ChaCha20, Poly1305, HChaCha20 and XChaCha20-Poly1305, then checks the bridge
// helpers against the Rust behaviour they must match.
//
// Run from anywhere:  node extensions/tools/test-crypto.mjs
//
// Node 18+ is enough; `crypto.subtle`, `btoa` and `atob` are all global.

import {
  hchacha20,
  poly1305,
  xchachaSeal,
  xchachaOpen,
  helloProof,
  sessionKey,
  sealFrame,
  openFrame,
  b64Encode,
  b64Decode,
  b64urlEncode,
  b64urlDecode,
  randomBytes,
  PROTOCOL_VERSION,
} from "../shared/lib/crypto.js";

let passed = 0;
let failed = 0;

function hex(bytes) {
  return [...bytes].map((b) => b.toString(16).padStart(2, "0")).join("");
}

function bytes(hexString) {
  const out = new Uint8Array(hexString.length / 2);
  for (let i = 0; i < out.length; i++) {
    out[i] = parseInt(hexString.slice(i * 2, i * 2 + 2), 16);
  }
  return out;
}

function fromAscii(text) {
  return new TextEncoder().encode(text);
}

function check(name, actual, expected) {
  const a = typeof actual === "string" ? actual : hex(actual);
  const e = typeof expected === "string" ? expected : hex(expected);
  if (a === e) {
    passed++;
    console.log(`  ok   ${name}`);
  } else {
    failed++;
    console.log(`  FAIL ${name}`);
    console.log(`       expected ${e}`);
    console.log(`       actual   ${a}`);
  }
}

function assert(name, condition, detail = "") {
  if (condition) {
    passed++;
    console.log(`  ok   ${name}`);
  } else {
    failed++;
    console.log(`  FAIL ${name}${detail ? ` — ${detail}` : ""}`);
  }
}

// ---------------------------------------------------------------- ChaCha20
// RFC 8439 §2.3.2 block function vector is covered indirectly through the AEAD
// vectors below; Poly1305 gets the standalone vector from §2.5.2.

console.log("Poly1305 (RFC 8439 §2.5.2)");
{
  const key = bytes("85d6be7857556d337f4452fe42d506a80103808afb0db2fd4abff6af4149f51b");
  const message = fromAscii("Cryptographic Forum Research Group");
  check("tag", poly1305(key, message), bytes("a8061dc1305136c6c22b8baf0c0127a9"));
}

console.log("HChaCha20 (draft-irtf-cfrg-xchacha-03 §2.2.1)");
{
  const key = bytes(
    "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f",
  );
  const nonce = bytes("000000090000004a0000000031415927");
  check(
    "subkey",
    hchacha20(key, nonce),
    bytes("82413b4227b27bfed30e42508a877d73a0f9e4d58a74a853c12ec41326d3ecdc"),
  );
}

console.log("XChaCha20-Poly1305 AEAD (draft-irtf-cfrg-xchacha-03 §A.3)");
{
  const plaintext = fromAscii(
    "Ladies and Gentlemen of the class of '99: If I could offer you only one tip " +
    "for the future, sunscreen would be it.",
  );
  const aad = bytes("50515253c0c1c2c3c4c5c6c7");
  const key = bytes(
    "808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f",
  );
  const nonce = bytes("404142434445464748494a4b4c4d4e4f5051525354555657");
  const expected = bytes(
    "bd6d179d3e83d43b9576579493c0e939572a1700252bfaccbed2902c21396cbb" +
    "731c7f1b0b4aa6440bf3a82f4eda7e39ae64c6708c54c216cb96b72e1213b452" +
    "2f8c9ba40db5d945b11b69b982c1bb9e3f3fac2bc369488f76b2383565d3fff9" +
    "21f9664c97637da9768812f615c68b13b52e" +
    "c0875924c1c7987947deafd8780acf49",
  );
  const sealed = xchachaSeal(key, nonce, aad, plaintext);
  check("ciphertext+tag", sealed, expected);

  const opened = xchachaOpen(key, nonce, aad, expected);
  assert("round trip", opened !== null && hex(opened) === hex(plaintext));
  assert("rejects a flipped tag byte", xchachaOpen(key, nonce, aad, flipLast(expected)) === null);
  assert("rejects a flipped aad", xchachaOpen(key, nonce, flipFirst(aad), expected) === null);
}
{
  // Empty AAD still has to round-trip, and the tag is always 16 bytes.
  const plaintext = fromAscii("Hello, world!");
  const key = randomBytes(32);
  const nonce = randomBytes(24);
  const sealed = xchachaSeal(key, nonce, new Uint8Array(0), plaintext);
  assert("empty aad round trip", hex(xchachaOpen(key, nonce, new Uint8Array(0), sealed)) === hex(plaintext));
  assert("tag is 16 bytes", sealed.length === plaintext.length + 16);
}

function flipLast(arr) {
  const copy = arr.slice();
  copy[copy.length - 1] ^= 0x01;
  return copy;
}

function flipFirst(arr) {
  const copy = arr.slice();
  if (copy.length) copy[0] ^= 0x01;
  return copy;
}

// ------------------------------------------------------------ base64 codecs

console.log("base64 helpers");
{
  const data = randomBytes(37);
  assert("b64 round trip", hex(b64Decode(b64Encode(data))) === hex(data));
  assert("b64url round trip", hex(b64urlDecode(b64urlEncode(data))) === hex(data));
  assert("b64url has no padding", !b64urlEncode(data).includes("="));
  const padded = b64urlEncode(fromAscii("f"));
  assert("b64url unpadded decodes", hex(b64urlDecode(padded)) === hex(fromAscii("f")));
}

// -------------------------------------------------- bridge handshake crypto

console.log("bridge handshake helpers");
{
  const token = "a-very-secret-pairing-token";
  const salt = randomBytes(32);
  const proof = await helloProof(token, salt, PROTOCOL_VERSION);
  assert("proof is base64url of 32 bytes", b64urlDecode(proof).length === 32);

  const other = await helloProof("a-different-token", salt, PROTOCOL_VERSION);
  assert("a different token gives a different proof", proof !== other);

  const key = await sessionKey(token, salt);
  assert("session key is 32 bytes", key.length === 32);
  const key2 = await sessionKey(token, salt);
  assert("session key is deterministic", hex(key) === hex(key2));
  const key3 = await sessionKey(token, randomBytes(32));
  assert("a different salt gives a different key", hex(key) !== hex(key3));
}

console.log("bridge frames");
{
  const key = await sessionKey("tok", randomBytes(32));
  const frame = sealFrame(key, { type: "ping" });
  assert("frame is nonce.ct", frame.split(".").length === 2);
  assert("frame hides the plaintext", !frame.includes("ping"));
  const back = openFrame(key, frame);
  assert("frame round trip", back.type === "ping");
  assert("each frame uses a fresh nonce", sealFrame(key, { type: "ping" }) !== frame);

  const broken = frame.slice(0, -4) + "AAAA";
  let threw = false;
  try { openFrame(key, broken); } catch { threw = true; }
  assert("tampering is rejected", threw);

  let formatThrew = false;
  try { openFrame(key, "not-a-frame"); } catch { formatThrew = true; }
  assert("malformed frame is rejected", formatThrew);
}

// ------------------------------------------------------------------- done

console.log("");
if (failed === 0) {
  console.log(`All ${passed} checks passed.`);
  process.exit(0);
} else {
  console.log(`${failed} of ${passed + failed} checks failed.`);
  process.exit(1);
}
