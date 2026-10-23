// Malformed and hostile inputs; archives are built in memory from fixed keys.

import assert from "node:assert/strict";
import crypto from "node:crypto";
import { EventEmitter } from "node:events";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { describe, test } from "node:test";
import zlib from "node:zlib";

import { AES, Entry, Interrupted, ZedArchive, ZedError, main, promptPassword, tlv, xor } from "../zed.js";

const hex = (value) => Buffer.from(value, "hex");
const KEY = Buffer.from(Array.from({ length: 16 }, (_, i) => i));
const IV = Buffer.from(Array.from({ length: 16 }, (_, i) => i + 16));
const FILE_ID = hex("f714c09327642647991ff50d4552fb00");
const ROOT = Buffer.alloc(16);
const MAGIC = hex("d0cf11e0a1b11ae1");

function tlvField(kind, value) {
  const head = Buffer.alloc(8);
  hex(kind).copy(head);
  head.writeUInt32BE(value.length, 4);
  return Buffer.concat([head, value]);
}

function id(n) {
  const out = Buffer.alloc(16);
  out.writeUInt32BE(n, 12);
  return out;
}

/** Inverse of AES.decryptZed for mode 103 (AES-CBC-STREAM). */
function encryptStream(aes, plain, key, iv) {
  const whole = Math.floor(plain.length / 16) * 16;
  const body = aes.cipher(plain.subarray(0, whole), key, iv, false);
  const tail = plain.subarray(whole);
  if (!tail.length) return body;
  const mask = aes.cipher(body.length ? body.subarray(-16) : iv, key, null, false);
  return Buffer.concat([body, xor(tail, mask.subarray(0, tail.length))]);
}

function archiveWith(entries) {
  const archive = Object.create(ZedArchive.prototype);
  archive.entries = entries;
  return archive;
}

function fileArchive(compressed, size) {
  const archive = archiveWith([new Entry(FILE_ID, ROOT, "f.bin", size, false)]);
  Object.assign(archive, { aes: new AES(), key: KEY, iv: IV, version: 1, mode: 103 });
  const chunks = [];
  for (let n = 0, pos = 0; pos < compressed.length; n++, pos += 512) {
    const counter = Buffer.alloc(16);
    counter.writeUInt32LE(n);
    const iv = archive.aes.cipher(xor(counter, IV), KEY, null, false);
    chunks.push(encryptStream(archive.aes, compressed.subarray(pos, pos + 512), KEY, iv));
  }
  const data = Buffer.concat(chunks);
  archive.cfb = { stream: () => data };
  return archive;
}

const dirEntry = (n, parent = ROOT, name = `d${n}`) => new Entry(id(n), parent, name, 0, true);

function tempDir() {
  return fs.mkdtempSync(path.join(os.tmpdir(), "zed-test-"));
}

function withTempDir(fn) {
  return async () => {
    const dir = tempDir();
    try {
      await fn(dir);
    } finally {
      fs.rmSync(dir, { recursive: true, force: true });
    }
  };
}

describe("file data", () => {
  test("round trip across chunks", async () => {
    const data = crypto.randomBytes(5000);
    const archive = fileArchive(zlib.deflateSync(data), data.length);
    assert.deepEqual(await archive.read(archive.entries[0]), data);
  });

  test("output larger than one piece", async () => {
    const data = Buffer.alloc(3 * ZedArchive.MAX_PIECE + 7);
    const archive = fileArchive(zlib.deflateSync(data), data.length);
    const pieces = [];
    for await (const piece of archive.iterRead(archive.entries[0])) pieces.push(piece);
    assert.deepEqual(Buffer.concat(pieces), data);
    assert.ok(Math.max(...pieces.map((p) => p.length)) <= ZedArchive.MAX_PIECE);
  });

  test("decompression stops at the catalog size", async () => {
    const archive = fileArchive(zlib.deflateSync(Buffer.alloc(50 << 20)), 10);
    let produced = 0;
    await assert.rejects(async () => {
      for await (const piece of archive.iterRead(archive.entries[0])) produced += piece.length;
    }, /size mismatch/);
    assert.ok(produced <= ZedArchive.MAX_PIECE);
  });

  test("short output is rejected", async () => {
    const archive = fileArchive(zlib.deflateSync(Buffer.from("abc")), 4);
    await assert.rejects(archive.read(archive.entries[0]), /size mismatch/);
  });

  test("truncated stream is rejected", async () => {
    const data = crypto.randomBytes(2000);
    const archive = fileArchive(zlib.deflateSync(data).subarray(0, -10), data.length);
    await assert.rejects(archive.read(archive.entries[0]), (error) =>
      error instanceof ZedError && /truncated stream/.test(error.message));
  });

  test("corrupt stream is rejected", async () => {
    const archive = fileArchive(Buffer.alloc(64, 0xff), 64);
    await assert.rejects(archive.read(archive.entries[0]), (error) =>
      error instanceof ZedError && /decompression failed/.test(error.message));
  });

  test("extract writes the file", withTempDir(async (dir) => {
    const data = crypto.randomBytes(3000);
    const written = await fileArchive(zlib.deflateSync(data), data.length).extractTo(dir);
    assert.deepEqual(written.map((p) => path.basename(p)), ["f.bin"]);
    assert.deepEqual(fs.readFileSync(written[0]), data);
  }));

  test("failed extract leaves no partial file", withTempDir(async (dir) => {
    const archive = fileArchive(zlib.deflateSync(Buffer.alloc(4 << 20)), 1 << 20);
    await assert.rejects(archive.extractTo(dir), ZedError);
    assert.deepEqual(fs.readdirSync(dir), []);
  }));

  test("interrupted extract leaves no partial file", withTempDir(async (dir) => {
    const data = crypto.randomBytes(3 * ZedArchive.MAX_PIECE);
    const archive = fileArchive(zlib.deflateSync(data), data.length);
    let checks = 0;
    // Passes the check before the file is opened, then aborts mid-file.
    const signal = { throwIfAborted() { if (++checks > 1) throw new Interrupted(); } };
    await assert.rejects(archive.extractTo(dir, { signal }), Interrupted);
    assert.deepEqual(fs.readdirSync(dir), []);
  }));
});

describe("catalog", () => {
  test("deep nesting", () => {
    const entries = [dirEntry(1)];
    for (let n = 2; n <= 3000; n++) entries.push(dirEntry(n, id(n - 1)));
    const parts = archiveWith(entries).names().at(-1)[1].split(path.sep);
    assert.equal(parts.length, 3000);
    assert.deepEqual(parts.slice(0, 2), ["d1", "d2"]);
  });

  test("cycle", () => {
    assert.throws(() => archiveWith([dirEntry(1, id(2)), dirEntry(2, id(1))]).names(), /cycle/);
  });

  for (const name of ["", ".", "..", "a/b", "a\\b", "C:x", "a\0"]) {
    test(`unsafe name ${JSON.stringify(name)}`, () => {
      assert.throws(() => archiveWith([dirEntry(1, ROOT, name)]).names(), /unsafe/);
    });
  }

  test("missing parent", () => {
    assert.throws(() => archiveWith([dirEntry(1, id(9))]).names(), /missing parent/);
  });

  async function assertRejectedBeforeWriting(entries) {
    const archive = archiveWith(entries);
    archive.iterRead = () => assert.fail("read before checks");
    const dir = tempDir();
    try {
      const out = path.join(dir, "out");
      await assert.rejects(archive.extractTo(out), /duplicate path/);
      assert.equal(fs.existsSync(out), false);
    } finally {
      fs.rmSync(dir, { recursive: true, force: true });
    }
  }

  test("duplicate files", () => assertRejectedBeforeWriting([
    new Entry(id(1), ROOT, "x", 1, false),
    new Entry(id(2), ROOT, "x", 1, false),
  ]));

  for (const [first, second] of [["A.txt", "a.txt"], ["café", "café"], ["straße", "STRASSE"]]) {
    test(`case and normalization collision ${first}`, () => assertRejectedBeforeWriting([
      new Entry(id(1), ROOT, first, 1, false),
      new Entry(id(2), ROOT, second, 1, false),
    ]));
  }

  test("file and directory collision", () => assertRejectedBeforeWriting([
    dirEntry(1, ROOT, "x"),
    new Entry(id(2), ROOT, "X", 1, false),
  ]));

  test("duplicate directories are allowed", withTempDir(async (dir) => {
    assert.deepEqual(await archiveWith([dirEntry(1, ROOT, "x"), dirEntry(2, ROOT, "x")]).extractTo(dir), []);
    assert.ok(fs.statSync(path.join(dir, "x")).isDirectory());
  }));

  test("existing symlink is not followed", withTempDir(async (dir) => {
    const outside = path.join(dir, "outside");
    fs.mkdirSync(outside);
    fs.symlinkSync(outside, path.join(dir, "d1"));
    const archive = archiveWith([dirEntry(1), new Entry(id(2), id(1), "f", 1, false)]);
    await assert.rejects(archive.extractTo(dir), /refusing to follow symlink/);
    assert.deepEqual(fs.readdirSync(outside), []);
  }));
});

describe("unlock", () => {
  const ARCHIVE_KEY = Buffer.from(Array.from({ length: 16 }, (_, i) => i + 100));
  const aes = new AES();

  function user(password, { corrupt = false, check } = {}) {
    const pw = Buffer.from(password);
    check ??= crypto.pbkdf2Sync(pw, "pba-salt", 1, 16, "sha256");
    const keyIv = crypto.pbkdf2Sync(pw, "key-salt", 1, 48, "sha256");
    let ciphertext = aes.cipher(Buffer.concat([ARCHIVE_KEY, Buffer.alloc(16, 16)]), keyIv.subarray(0, 16), keyIv.subarray(32, 48), false);
    // Changing the first block garbles the padding in the second.
    if (corrupt) ciphertext = Buffer.concat([Buffer.alloc(16), ciphertext.subarray(16)]);
    const one = hex("00000001");
    return tlvField("80610600", Buffer.concat([
      tlvField("80780200", hex("0000002a")), tlvField("80790500", check),
      tlvField("807a0500", Buffer.from("pba-salt")), tlvField("807b0200", one),
      tlvField("80760500", Buffer.from("key-salt")), tlvField("80770200", one),
      tlvField("80740500", ciphertext),
    ]));
  }

  function unlock(users, password = "secret") {
    const archive = Object.assign(archiveWith([]), { aes, strength: 16 });
    return archive._unlock(tlv(Buffer.concat(users)), password);
  }

  test("valid user", () => {
    assert.deepEqual(unlock([user("secret")]), ARCHIVE_KEY);
  });

  test("bad key falls through to the next user", () => {
    assert.deepEqual(unlock([user("secret", { corrupt: true }), user("secret")]), ARCHIVE_KEY);
  });

  test("bad key is reported when no user unlocks", () => {
    assert.throws(() => unlock([user("secret", { corrupt: true })]), /padding/);
  });

  test("empty verifier never matches", () => {
    assert.throws(() => unlock([user("secret", { check: Buffer.alloc(0) })]), /does not match/);
  });

  test("wrong password", () => {
    assert.throws(() => unlock([user("secret")], "other"), /does not match/);
  });
});

describe("container", () => {
  function openBytes(data) {
    const dir = tempDir();
    try {
      const file = path.join(dir, "a.zed");
      fs.writeFileSync(file, data);
      return new ZedArchive(file, "pw");
    } finally {
      fs.rmSync(dir, { recursive: true, force: true });
    }
  }

  test("truncated header", () => {
    assert.throws(() => openBytes(MAGIC), (error) => error instanceof ZedError && /malformed archive/.test(error.message));
  });

  test("not OLE", () => {
    assert.throws(() => openBytes(Buffer.alloc(1024)), /not an OLE/);
  });

  test("DIFAT cycle", () => {
    const header = Buffer.alloc(512);
    MAGIC.copy(header);
    header.writeUInt16LE(9, 30);
    header.writeUInt16LE(6, 32);
    header.writeUInt32LE(0, 68); // first DIFAT sector
    header.writeUInt32LE(0xffffffff, 72); // DIFAT count
    header.fill(0xff, 76);
    const sector = Buffer.alloc(512, 0xff);
    sector.writeUInt32LE(0, 508); // points back to itself
    assert.throws(() => openBytes(Buffer.concat([header, sector])), /DIFAT/);
  });
});

class FakeInput extends EventEmitter {
  constructor(chunks, { tty }) {
    super();
    this.chunks = chunks;
    this.isTTY = tty;
    this.rawModes = [];
    if (tty) this.setRawMode = (mode) => this.rawModes.push(mode);
  }

  setEncoding() {}

  pause() {}

  resume() {
    setImmediate(() => {
      for (const chunk of this.chunks) this.emit("data", chunk);
      if (!this.isTTY) this.emit("end");
    });
  }
}

const sink = () => ({ text: "", write(chunk) { this.text += chunk; } });

describe("password prompt", () => {
  test("terminal input is not echoed and supports backspace", async () => {
    const input = new FakeInput(["ab", "\u007fc", "\r"], { tty: true });
    const output = sink();
    assert.equal(await promptPassword("pw: ", { input, output }), "ac");
    assert.equal(output.text, "pw: \n");
    assert.deepEqual(input.rawModes, [true, false]);
  });

  test("Ctrl-C at the terminal interrupts", async () => {
    const input = new FakeInput(["ab\u0003"], { tty: true });
    await assert.rejects(promptPassword("pw: ", { input, output: sink() }), Interrupted);
    assert.deepEqual(input.rawModes, [true, false]);
  });

  test("piped input reads one line", async () => {
    const input = new FakeInput(["sec", "ret\r\nrest\n"], { tty: false });
    assert.equal(await promptPassword("pw: ", { input, output: sink() }), "secret");
  });

  test("empty piped input interrupts", async () => {
    await assert.rejects(promptPassword("pw: ", { input: new FakeInput([], { tty: false }), output: sink() }), Interrupted);
  });
});

describe("command line", () => {
  async function run(argv, prompt = async () => "pw") {
    const stdout = sink();
    const stderr = sink();
    let prompted = false;
    const code = await main(argv, {
      stdout,
      stderr,
      signals: new EventEmitter(),
      prompt: (...args) => { prompted = true; return prompt(...args); },
    });
    return { code, out: stdout.text, err: stderr.text, prompted };
  }

  test("missing archive fails before the prompt", async () => {
    const result = await run(["/nonexistent/a.zed"]);
    assert.equal(result.code, 1);
    assert.match(result.err, /not a file/);
    assert.equal(result.prompted, false);
  });

  test("malformed archive reports an error", withTempDir(async (dir) => {
    const file = path.join(dir, "a.zed");
    fs.writeFileSync(file, MAGIC);
    const result = await run([file]);
    assert.equal(result.code, 1);
    assert.match(result.err, /^zed: malformed archive/);
  }));

  test("interrupt at the prompt", withTempDir(async (dir) => {
    const file = path.join(dir, "a.zed");
    fs.writeFileSync(file, "");
    const result = await run([file], async () => { throw new Interrupted(); });
    assert.equal(result.code, 130);
    assert.match(result.err, /interrupted/);
  }));

  test("usage errors", async () => {
    assert.equal((await run([])).code, 2);
    assert.equal((await run(["--bogus", "a.zed"])).code, 2);
  });

  test("help", async () => {
    const result = await run(["--help"]);
    assert.equal(result.code, 0);
    assert.match(result.out, /^usage: zed/);
  });
});
