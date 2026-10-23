// Published Zed format vectors; no archive password is stored here.

import assert from "node:assert/strict";
import { test } from "node:test";
import zlib from "node:zlib";

import { AES, pkcs12Kdf } from "../zed.js";

const hex = (value) => Buffer.from(value, "hex");
const aes = new AES();
const utf16 = (data) => data.toString("utf16le").replace(/\0+$/, "");

test("stream mode, short filename", () => {
  const plain = aes.decryptZed(
    hex("6905386c749b7fc088ca40b0419a"),
    hex("4a85bda3df4df0ea3090cc21618901ee"),
    hex("f266ef5a855d0494b6c9a9a8325a4415"),
    103,
  );
  assert.equal(utf16(plain), "abc.txt");
});

test("CTS mode, partial filename", () => {
  const plain = aes.decryptZed(
    hex("3842bf4e19ccce83deaf9cdf763cdd713d7b"),
    hex("dc30c294eb879cc505961f042ca790d4"),
    hex("696eb7b48347ade4b3d7a0812bc695ea"),
    104,
  );
  assert.equal(utf16(plain), "empty.txt");
});

test("CTS mode, block-aligned file", () => {
  const key = hex("855ecc286bb4f1adab26bd39514d4f4eb60181849c3bc605fb3fb78846e0cfef");
  const globalIv = hex("bf205053393a02f3927c8f0836660a9f");
  const ciphertext = hex("5baf62282f9e23d0974aad6eb4f3970da9ac7e5c54356d1c0f5918e378595ba3");
  const chunkIv = aes.cipher(globalIv, key, null, false);
  const compressed = aes.decryptZed(ciphertext, key, chunkIv, 104);
  assert.deepEqual(zlib.inflateSync(compressed), Buffer.from("1234567890".repeat(160)));
});

test("PKCS#12 SHA-1 password check", () => {
  assert.equal(pkcs12Kdf("123456", hex("d0ee7a995bf3022e"), 200000, "sha1", 3, 8).toString("hex"), "98a431f7e9eda53f");
});
