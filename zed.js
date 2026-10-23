#!/usr/bin/env node
/**
 * Small, read-only .zed archive extractor (password users only).
 *
 * Node.js port of zed.py, based on the format description at
 * https://www.beuc.net/zed/ . Uses only Node's built-in modules.
 */

import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import { Readable } from "node:stream";
import { fileURLToPath } from "node:url";
import { parseArgs } from "node:util";
import zlib from "node:zlib";

export class ZedError extends Error {
  constructor(message, options) {
    super(message, options);
    this.name = "ZedError";
  }
}

export class Interrupted extends Error {
  constructor() {
    super("interrupted");
    this.name = "Interrupted";
  }
}

const hex = (value) => Buffer.from(value, "hex");
const quote = (value) => JSON.stringify(value);
const UTF16LE = new TextDecoder("utf-16le", { fatal: true, ignoreBOM: true });

function u32be(data) {
  if (data.length !== 4) throw new ZedError("invalid uint32 field");
  return data.readUInt32BE(0);
}

function u32leArray(data, offset, count) {
  return Array.from({ length: count }, (_, i) => data.readUInt32LE(offset + 4 * i));
}

export function xor(a, b) {
  if (a.length !== b.length) throw new ZedError("xor length mismatch");
  const out = Buffer.alloc(a.length);
  for (let i = 0; i < a.length; i++) out[i] = a[i] ^ b[i];
  return out;
}

function decodeUtf16le(data) {
  try {
    return UTF16LE.decode(data);
  } catch {
    throw new ZedError("malformed archive: invalid UTF-16 text");
  }
}

function startsWith(data, prefix) {
  return data.length >= prefix.length && data.subarray(0, prefix.length).equals(prefix);
}

function endsWith(data, suffix) {
  return data.length >= suffix.length && data.subarray(data.length - suffix.length).equals(suffix);
}

export class CFB {
  static END = 0xfffffffe;
  static FREE = 0xffffffff;

  constructor(data) {
    this.data = data;
    if (!startsWith(data, hex("d0cf11e0a1b11ae1"))) throw new ZedError("not an OLE/CFB file");
    this.sectorSize = 2 ** data.readUInt16LE(30);
    this.miniSize = 2 ** data.readUInt16LE(32);
    if (![512, 4096].includes(this.sectorSize) || this.miniSize !== 64) {
      throw new ZedError("unsupported CFB sector size");
    }
    this.miniCutoff = data.readUInt32LE(56);
    const fatCount = data.readUInt32LE(44);
    const difat = u32leArray(data, 76, 109);
    let nextDifat = data.readUInt32LE(68);
    const seen = new Set();
    const difatCount = data.readUInt32LE(72);
    for (let i = 0; i < difatCount; i++) {
      if (seen.has(nextDifat)) throw new ZedError("invalid CFB DIFAT chain");
      seen.add(nextDifat);
      const entries = u32leArray(this.sector(nextDifat), 0, this.sectorSize / 4);
      difat.push(...entries.slice(0, -1));
      nextDifat = entries.at(-1);
    }
    const fatSectors = difat.filter((sid) => sid !== CFB.FREE).slice(0, fatCount);
    if (fatSectors.length !== fatCount) throw new ZedError("truncated CFB allocation table");
    this.fat = fatSectors.flatMap((sid) => u32leArray(this.sector(sid), 0, this.sectorSize / 4));
    const directory = this.chain(data.readUInt32LE(48), this.fat);
    this.entries = new Map();
    this.root = null;
    for (let pos = 0; pos + 128 <= directory.length; pos += 128) {
      const record = directory.subarray(pos, pos + 128);
      const kind = record[66];
      if (![1, 2, 5].includes(kind)) continue;
      const nameLength = record.readUInt16LE(64);
      if (nameLength < 2 || nameLength > 64) continue;
      const name = decodeUtf16le(record.subarray(0, nameLength - 2));
      // Sizes beyond 2^53 lose precision but still exceed any in-memory file.
      const item = { kind, start: record.readUInt32LE(116), size: Number(record.readBigUInt64LE(120)) };
      this.entries.set(name, item);
      if (kind === 5) this.root = item;
    }
    if (this.root === null) throw new ZedError("missing CFB root entry");
    const miniStart = data.readUInt32LE(60);
    const miniCount = data.readUInt32LE(64);
    const rawMinifat = miniCount ? this.chain(miniStart, this.fat, miniCount) : Buffer.alloc(0);
    this.minifat = u32leArray(rawMinifat, 0, Math.floor(rawMinifat.length / 4));
    this.ministream = this.chain(this.root.start, this.fat).subarray(0, this.root.size);
  }

  sector(sid) {
    const start = (sid + 1) * this.sectorSize;
    if (start + this.sectorSize > this.data.length) throw new ZedError("CFB sector outside file");
    return this.data.subarray(start, start + this.sectorSize);
  }

  chain(start, table, limit = Infinity) {
    const parts = [];
    const seen = new Set();
    while (start !== CFB.END && parts.length < limit) {
      if (seen.has(start) || start >= table.length) throw new ZedError("invalid CFB sector chain");
      seen.add(start);
      parts.push(this.sector(start));
      start = table[start];
    }
    return Buffer.concat(parts);
  }

  stream(name) {
    const item = this.entries.get(name);
    if (item === undefined) throw new ZedError(`missing CFB stream ${quote(name)}`);
    let { kind, start, size } = item;
    if (kind !== 2) throw new ZedError(`not a CFB stream: ${quote(name)}`);
    if (size >= this.miniCutoff) {
      const result = this.chain(start, this.fat);
      if (result.length < size) throw new ZedError("truncated CFB stream");
      return result.subarray(0, size);
    }
    const parts = [];
    const seen = new Set();
    while (start !== CFB.END && parts.length * this.miniSize < size) {
      if (seen.has(start) || start >= this.minifat.length) throw new ZedError("invalid CFB mini-sector chain");
      seen.add(start);
      const offset = start * this.miniSize;
      parts.push(this.ministream.subarray(offset, offset + this.miniSize));
      start = this.minifat[start];
    }
    const result = Buffer.concat(parts);
    if (result.length < size) throw new ZedError("truncated CFB stream");
    return result.subarray(0, size);
  }
}

export class AES {
  cipher(data, key, iv, decrypt) {
    if (![16, 24, 32].includes(key.length) || data.length % 16) {
      throw new ZedError("invalid AES key or block length");
    }
    if (iv !== null && iv.length !== 16) throw new ZedError("invalid AES IV");
    const algorithm = `aes-${key.length * 8}-${iv === null ? "ecb" : "cbc"}`;
    const context = decrypt
      ? crypto.createDecipheriv(algorithm, key, iv)
      : crypto.createCipheriv(algorithm, key, iv);
    context.setAutoPadding(false);
    return Buffer.concat([context.update(data), context.final()]);
  }

  decryptZed(ciphertext, key, iv, mode) {
    if (iv.length !== 16) throw new ZedError("invalid AES IV");
    const whole = Math.floor(ciphertext.length / 16) * 16;
    const tail = ciphertext.subarray(whole);
    if (!tail.length) {
      // CBC-CS3 swaps the final two ciphertext blocks even when the
      // plaintext length is a multiple of the AES block size.
      if (mode === 104 && whole >= 32) {
        ciphertext = Buffer.concat([ciphertext.subarray(0, -32), ciphertext.subarray(-16), ciphertext.subarray(-32, -16)]);
      }
      return this.cipher(ciphertext, key, iv, true);
    }
    if (mode === 103 || whole === 0) {
      const prefix = this.cipher(ciphertext.subarray(0, whole), key, iv, true);
      const preceding = whole ? ciphertext.subarray(whole - 16, whole) : iv;
      const mask = this.cipher(preceding, key, null, false);
      return Buffer.concat([prefix, xor(tail, mask.subarray(0, tail.length))]);
    }
    if (mode !== 104) throw new ZedError(`unsupported encryption mode ${mode}`);
    const before = ciphertext.subarray(0, whole - 16);
    const finalFull = ciphertext.subarray(whole - 16, whole);
    const preceding = before.length ? before.subarray(-16) : iv;
    const x = this.cipher(finalFull, key, null, true);
    const stolen = Buffer.concat([tail, x.subarray(tail.length)]);
    const lastPartial = xor(x.subarray(0, tail.length), tail);
    const lastFull = xor(this.cipher(stolen, key, null, true), preceding);
    return Buffer.concat([this.cipher(before, key, iv, true), lastFull, lastPartial]);
  }
}

export function pkcs12Kdf(password, salt, iterations, digest, purpose, length) {
  if (iterations < 1 || iterations > 10_000_000) throw new ZedError("invalid PKCS#12 iteration count");
  const v = 64; // SHA-1 and SHA-256 block size
  // Buffer.alloc repeats a Buffer fill value, which is exactly the expansion step.
  const expand = (source) => (source.length ? Buffer.alloc(v * Math.ceil(source.length / v), source) : Buffer.alloc(0));
  const p = Buffer.concat([Buffer.from(password, "utf16le").swap16(), Buffer.alloc(2)]);
  const blocks = Buffer.concat([expand(salt), expand(p)]);
  const diversifier = Buffer.alloc(v, purpose);
  const result = [];
  let produced = 0;
  while (produced < length) {
    let a = Buffer.concat([diversifier, blocks]);
    for (let i = 0; i < iterations; i++) a = crypto.createHash(digest).update(a).digest();
    result.push(a);
    produced += a.length;
    const b = Buffer.alloc(v, a);
    for (let offset = 0; offset < blocks.length; offset += v) {
      // I_j = (I_j + B + 1) mod 2^(8v), big-endian.
      let carry = 1;
      for (let k = v - 1; k >= 0; k--) {
        const sum = blocks[offset + k] + b[k] + carry;
        blocks[offset + k] = sum & 0xff;
        carry = sum >> 8;
      }
    }
  }
  return Buffer.concat(result).subarray(0, length);
}

export function tlv(data) {
  const fields = [];
  let pos = 0;
  while (pos < data.length) {
    if (data.length - pos < 8) throw new ZedError("truncated TLV header");
    const kind = data.subarray(pos, pos + 4);
    const size = data.readUInt32BE(pos + 4);
    pos += 8;
    if (size > data.length - pos) throw new ZedError("truncated TLV value");
    fields.push([kind, data.subarray(pos, pos + size)]);
    pos += size;
  }
  return fields;
}

function field(fields, kind) {
  const tag = hex(kind);
  for (const [current, value] of fields) {
    if (current.equals(tag)) return value;
  }
  throw new ZedError(`missing TLV field ${kind}`);
}

function propertyBlobs(stream) {
  if (stream.length < 48 || stream[0] !== 0xfe || stream[1] !== 0xff) {
    throw new ZedError("invalid OLE property stream");
  }
  const sectionCount = stream.readUInt32LE(24);
  const result = new Map();
  for (let sectionIndex = 0; sectionIndex < sectionCount; sectionIndex++) {
    const sectionOffset = stream.readUInt32LE(28 + 20 * sectionIndex + 16);
    if (sectionOffset + 8 > stream.length) throw new ZedError("invalid OLE property section");
    const count = stream.readUInt32LE(sectionOffset + 4);
    for (let index = 0; index < count; index++) {
      const propId = stream.readUInt32LE(sectionOffset + 8 + 8 * index);
      const start = sectionOffset + stream.readUInt32LE(sectionOffset + 12 + 8 * index);
      if (start + 8 > stream.length) throw new ZedError("invalid OLE property offset");
      if (stream.readUInt32LE(start) === 0x41) { // VT_BLOB
        const length = stream.readUInt32LE(start + 4);
        if (start + 8 + length > stream.length) throw new ZedError("truncated OLE blob");
        result.set(propId, stream.subarray(start + 8, start + 8 + length));
      }
    }
  }
  return result;
}

function stripNulUtf16(data) {
  return decodeUtf16le(data).replace(/\0+$/, "");
}

function fileSize(data) {
  let size = 0n;
  for (let i = data.length - 1; i >= 0; i--) size = (size << 8n) | BigInt(data[i]);
  if (size > BigInt(Number.MAX_SAFE_INTEGER)) throw new ZedError("invalid file size in catalog");
  return Number(size);
}

function isSystemError(error) {
  return error instanceof Error && typeof error.code === "string" && typeof error.syscall === "string";
}

function realpathIfExists(target) {
  try {
    return fs.realpathSync(target);
  } catch (error) {
    if (error.code === "ENOENT") return target;
    throw error;
  }
}

function writeAll(fd, data) {
  for (let offset = 0; offset < data.length;) offset += fs.writeSync(fd, data, offset);
}

export class Entry {
  constructor(fileId, parentId, name, size, isDir) {
    Object.assign(this, { fileId, parentId, name, size, isDir });
  }
}

const TAG = {
  fileprops: hex("80110600"),
  user: hex("80610600"),
  isDir: hex("80320100"),
};
const HASHES = new Map([[21, "sha1"], [22, "sha256"]]);

export class ZedArchive {
  static METADATA_NAME = "\x05" + "5haaaaqaIekzeecnWj31zxh0Nc";
  static DELIMITER = hex("0765921a2a0774534752073361719300");
  static STATIC_KEY = hex("37f13cf81c780af26b6a52654f794aef");
  static MAX_PIECE = 1 << 16;

  constructor(file, password) {
    const data = fs.readFileSync(file);
    try {
      this._parse(data, password);
    } catch (error) {
      // Truncated or inconsistent structures surface as out-of-range buffer reads.
      if (error instanceof RangeError) throw new ZedError(`malformed archive: ${error.message}`, { cause: error });
      throw error;
    }
  }

  _parse(data, password) {
    this.cfb = new CFB(data);
    this.aes = new AES();
    const blobs = propertyBlobs(this.cfb.stream(ZedArchive.METADATA_NAME));
    const controlIds = [...blobs].filter(([, blob]) => startsWith(blob, ZedArchive.DELIMITER)).map(([id]) => id);
    if (controlIds.length !== 1 || !blobs.has(controlIds[0] + 1)) {
      throw new ZedError("missing _ctlfile or _catalog property");
    }
    const ctl = blobs.get(controlIds[0]);
    const catalog = blobs.get(controlIds[0] + 1);
    if (ctl.length < 18 || ![1, 2].includes(ctl.readUInt16LE(16))) throw new ZedError("invalid _ctlfile header");
    this.version = ctl.readUInt16LE(16);
    const trailer = Buffer.concat([ZedArchive.DELIMITER, Buffer.from("ZoneCentral (R)\0", "latin1")]);
    if (!endsWith(ctl, trailer)) throw new ZedError("invalid _ctlfile trailer");
    if (ctl.length < 34 + 4 + trailer.length) throw new ZedError("invalid _ctlfile length");
    const iv = ctl.subarray(18, 34);
    const end = ctl.length - trailer.length;
    const ciphertext = ctl.subarray(34, end - 4);
    if (ctl.readUInt32BE(end - 4) !== 34 + ciphertext.length) throw new ZedError("invalid _ctlfile length");
    const control = tlv(this.aes.decryptZed(ciphertext, ZedArchive.STATIC_KEY, iv, 103));
    const props = tlv(field(control, "80110600"));
    this.mode = u32be(field(props, "80270200"));
    this.strength = u32be(field(props, "80260200"));
    this.iv = field(props, "80280500");
    if (![103, 104].includes(this.mode) || ![16, 24, 32].includes(this.strength) || this.iv.length !== 16) {
      throw new ZedError("unsupported archive encryption settings");
    }
    const users = tlv(field(control, "80140600"));
    this.key = this._unlock(users, password);
    this.entries = [];
    for (const [kind, value] of tlv(catalog)) {
      if (!kind.equals(TAG.fileprops)) continue;
      const fileProps = tlv(value);
      const fileId = field(fileProps, "80300500");
      const parentId = field(fileProps, "00370500");
      const encryptedName = field(fileProps, "00380500");
      if (fileId.length !== 16 || parentId.length !== 16) throw new ZedError("invalid catalog file id");
      const nameIv = this.version === 2 ? xor(this.iv, fileId) : this.iv;
      const name = stripNulUtf16(this.aes.decryptZed(encryptedName, this.key, nameIv, this.mode));
      const size = fileSize(field(fileProps, "80330500"));
      const isDir = fileProps.some(([k, v]) => k.equals(TAG.isDir) && u32be(v) === 1);
      this.entries.push(new Entry(fileId, parentId, name, size, isDir));
    }
  }

  _unlock(users, password) {
    let failure = null;
    for (const [kind, value] of users) {
      if (!kind.equals(TAG.user)) continue;
      const user = tlv(value);
      const hashId = u32be(field(user, "80780200"));
      const digest = HASHES.get(hashId);
      if (digest === undefined && hashId !== 42) continue;
      const check = field(user, "80790500");
      if (!check.length) continue;
      const pbaSalt = field(user, "807a0500");
      const pbaIter = u32be(field(user, "807b0200"));
      if (pbaIter < 1 || pbaIter > 10_000_000) throw new ZedError("invalid password iteration count");
      const secret = Buffer.from(password, "utf8");
      const derived = hashId === 42
        ? crypto.pbkdf2Sync(secret, pbaSalt, pbaIter, check.length, "sha256")
        : pkcs12Kdf(password, pbaSalt, pbaIter, digest, 3, check.length);
      if (!crypto.timingSafeEqual(derived, check)) continue;
      const salt = field(user, "80760500");
      const iterations = u32be(field(user, "80770200"));
      if (iterations < 1 || iterations > 10_000_000) throw new ZedError("invalid password iteration count");
      let key, iv;
      if (hashId === 42) {
        const keyIv = crypto.pbkdf2Sync(secret, salt, iterations, 48, "sha256");
        [key, iv] = [keyIv.subarray(0, this.strength), keyIv.subarray(32, 48)];
      } else {
        key = pkcs12Kdf(password, salt, iterations, digest, 1, 32).subarray(0, this.strength);
        iv = pkcs12Kdf(password, salt, iterations, digest, 2, 16);
      }
      const plaintext = this.aes.cipher(field(user, "80740500"), key, iv, true);
      const pad = plaintext.length ? plaintext.at(-1) : 0;
      if (pad < 1 || pad > 16 || !plaintext.subarray(-pad).equals(Buffer.alloc(pad, pad))) {
        // Another user entry may still unlock the archive.
        failure = new ZedError("invalid archive key padding");
        continue;
      }
      const archiveKey = plaintext.subarray(0, -pad);
      if (archiveKey.length !== this.strength) {
        failure = new ZedError("invalid archive key length");
        continue;
      }
      return archiveKey;
    }
    throw failure ?? new ZedError("password does not match any supported password user");
  }

  names() {
    const byId = new Map(this.entries.map((entry) => [entry.fileId.toString("hex"), entry]));
    const relative = (entry) => {
      // Walk up iteratively so deeply nested catalogs cannot exhaust the stack.
      const parts = [];
      const seen = new Set();
      for (;;) {
        const id = entry.fileId.toString("hex");
        if (seen.has(id)) throw new ZedError("directory cycle in catalog");
        seen.add(id);
        // Zed archives come from Windows, where ":" never appears in a
        // filename; rejecting it also blocks drive-relative paths.
        if (["", ".", ".."].includes(entry.name) || /[/\\:\0]/.test(entry.name)) {
          throw new ZedError("unsafe filename in catalog");
        }
        parts.push(entry.name);
        if (!entry.parentId.some((byte) => byte !== 0)) return path.join(...parts.reverse());
        const parent = byId.get(entry.parentId.toString("hex"));
        if (parent === undefined || !parent.isDir) throw new ZedError("missing parent directory");
        entry = parent;
      }
    };
    return this.entries.map((entry) => [entry, relative(entry)]);
  }

  async read(entry) {
    const pieces = [];
    for await (const piece of this.iterRead(entry)) pieces.push(piece);
    return Buffer.concat(pieces);
  }

  /** Yield decompressed pieces; output never exceeds the catalog size. */
  async *iterRead(entry) {
    if (entry.isDir) throw new ZedError("cannot read a directory");
    const fid = entry.fileId;
    if (fid.length !== 16) throw new ZedError("invalid file id");
    const shuffled = Buffer.from([3, 2, 1, 0, 5, 4, 7, 6, 8, 9, 10, 11, 12, 13, 14, 15].map((i) => fid[i]));
    const name = (shuffled[15] === 0 ? shuffled.subarray(0, 15) : shuffled).toString("hex").toUpperCase();
    const encrypted = this.cfb.stream(name);
    const { aes, key, mode } = this;
    const baseIv = this.version === 2 ? xor(this.iv, fid) : this.iv;
    function* decrypted() {
      for (let n = 0, pos = 0; pos < encrypted.length; n++, pos += 512) {
        const counter = Buffer.alloc(16);
        counter.writeUIntLE(n, 0, 6);
        // Version 2 mixes the file id into the IV before chunk numbering.
        const iv = aes.cipher(xor(counter, baseIv), key, null, false);
        yield aes.decryptZed(encrypted.subarray(pos, pos + 512), key, iv, mode);
      }
    }
    const source = Readable.from(decrypted());
    // The stream pulls input only as pieces are consumed, so memory stays bounded.
    const inflate = zlib.createInflate({ chunkSize: ZedArchive.MAX_PIECE });
    source.on("error", (error) => inflate.destroy(error));
    source.pipe(inflate);
    let produced = 0;
    try {
      for await (const piece of inflate) {
        produced += piece.length;
        if (produced > entry.size) throw new ZedError(`size mismatch for ${quote(entry.name)}`);
        yield piece;
      }
    } catch (error) {
      if (error instanceof ZedError) throw error;
      if (error?.code === "Z_BUF_ERROR") {
        throw new ZedError(`decompression failed for ${quote(entry.name)}: truncated stream`, { cause: error });
      }
      if (typeof error?.code === "string" && error.code.startsWith("Z_")) {
        throw new ZedError(`decompression failed for ${quote(entry.name)}: ${error.message}`, { cause: error });
      }
      throw error;
    } finally {
      source.destroy();
      inflate.destroy();
    }
    if (produced !== entry.size) throw new ZedError(`size mismatch for ${quote(entry.name)}`);
  }

  async extractTo(output, { progress, signal } = {}) {
    const root = realpathIfExists(path.resolve(output));
    const names = this.names();
    // Check every path before writing any files.
    const claimed = new Map();
    for (const [entry, relative] of names) {
      // Zed archives come from case-insensitive Windows, and macOS folds
      // case and Unicode normalization, so treat such names as one path.
      const key = relative.normalize("NFC").toUpperCase().toLowerCase();
      const other = claimed.get(key);
      if (other === undefined) claimed.set(key, entry);
      else if (!(entry.isDir && other.isDir)) throw new ZedError(`duplicate path in archive: ${relative}`);
      let current = root;
      for (const component of relative.split(path.sep)) {
        current = path.join(current, component);
        if (fs.lstatSync(current, { throwIfNoEntry: false })?.isSymbolicLink()) {
          throw new ZedError(`refusing to follow symlink ${current}`);
        }
      }
      const stat = fs.lstatSync(current, { throwIfNoEntry: false });
      if (entry.isDir && stat && !stat.isDirectory()) throw new ZedError(`not a directory: ${current}`);
      if (!entry.isDir && stat) throw new ZedError(`refusing to overwrite ${current}`);
    }
    fs.mkdirSync(root, { recursive: true });
    const total = names.filter(([entry]) => !entry.isDir).length;
    const written = [];
    for (const [entry, relative] of names) {
      signal?.throwIfAborted();
      const target = path.join(root, relative);
      if (entry.isDir) {
        fs.mkdirSync(target, { recursive: true });
        continue;
      }
      fs.mkdirSync(path.dirname(target), { recursive: true });
      const fd = fs.openSync(target, "wx");
      try {
        try {
          for await (const piece of this.iterRead(entry)) {
            signal?.throwIfAborted();
            writeAll(fd, piece);
          }
        } finally {
          fs.closeSync(fd);
        }
      } catch (error) {
        // Don't leave a partial file behind; it was created by us above.
        fs.rmSync(target, { force: true });
        throw error;
      }
      written.push(target);
      progress?.(written.length, total, target);
    }
    return written;
  }
}

/** Read a password without echoing it; falls back to one line of piped input. */
export function promptPassword(message, { input = process.stdin, output = process.stderr } = {}) {
  return new Promise((resolve, reject) => {
    const raw = Boolean(input.isTTY && input.setRawMode);
    let value = "";
    const finish = (error) => {
      input.off("data", onData);
      input.off("end", onEnd);
      if (raw) input.setRawMode(false);
      input.pause();
      output.write("\n");
      if (error) reject(error);
      else resolve(value);
    };
    const onEnd = () => (value && !raw ? finish() : finish(new Interrupted()));
    const onData = (chunk) => {
      if (!raw) {
        const newline = chunk.indexOf("\n");
        if (newline === -1) {
          value += chunk;
          return;
        }
        value = (value + chunk.slice(0, newline)).replace(/\r$/, "");
        finish();
        return;
      }
      // Ignore escape sequences such as arrow keys.
      if (chunk.startsWith("\u001b")) return;
      for (const ch of chunk) {
        if (ch === "\r" || ch === "\n") return finish();
        if (ch === "\u0003") return finish(new Interrupted()); // Ctrl-C
        if (ch === "\u0004") { // Ctrl-D
          if (!value) return finish(new Interrupted());
          continue;
        }
        if (ch === "\u007f" || ch === "\b") {
          value = Array.from(value).slice(0, -1).join("");
          continue;
        }
        if (ch >= " ") value += ch;
      }
    };
    // Disable echo before showing the prompt so early keystrokes are not echoed.
    if (raw) input.setRawMode(true);
    output.write(message);
    input.setEncoding("utf8");
    input.on("data", onData);
    input.on("end", onEnd);
    input.resume();
  });
}

const USAGE = "usage: zed [-h] [-o OUTPUT] [--list] archive\n";
const HELP = `${USAGE}
List or extract password-protected .zed archives

positional arguments:
  archive

options:
  -h, --help            show this help message and exit
  -o, --output OUTPUT   extract into this directory
  --list                list files without extracting
`;

function isFile(target) {
  try {
    return fs.statSync(target).isFile();
  } catch {
    return false;
  }
}

export async function main(argv = process.argv.slice(2), io = {}) {
  const { stdout = process.stdout, stderr = process.stderr, prompt = promptPassword, signals = process } = io;
  let args;
  try {
    args = parseArgs({
      args: argv,
      allowPositionals: true,
      options: {
        output: { type: "string", short: "o" },
        list: { type: "boolean" },
        help: { type: "boolean", short: "h" },
      },
    });
  } catch (error) {
    stderr.write(`${USAGE}zed: ${error.message}\n`);
    return 2;
  }
  if (args.values.help) {
    stdout.write(HELP);
    return 0;
  }
  if (args.positionals.length !== 1) {
    stderr.write(`${USAGE}zed: expected exactly one archive\n`);
    return 2;
  }
  const [archivePath] = args.positionals;
  const { output, list } = args.values;
  // Fail before prompting rather than after the password has been typed.
  if (!isFile(archivePath)) {
    stderr.write(`zed: not a file: ${archivePath}\n`);
    return 1;
  }
  const controller = new AbortController();
  const onInterrupt = () => controller.abort(new Interrupted());
  try {
    const password = await prompt("Zed password: ");
    const archive = new ZedArchive(archivePath, password);
    const names = archive.names();
    if (list || output === undefined) {
      for (const [entry, relative] of names) {
        stdout.write(`${entry.isDir ? "d" : "f"} ${String(entry.size).padStart(10)}  ${relative}\n`);
      }
    }
    if (output !== undefined) {
      // Stop between pieces on Ctrl-C so the partial file is removed.
      signals.on("SIGINT", onInterrupt);
      for (const target of await archive.extractTo(output, { signal: controller.signal })) {
        stdout.write(`${target}\n`);
      }
    }
  } catch (error) {
    if (error instanceof Interrupted) {
      stderr.write("\nzed: interrupted\n");
      return 130;
    }
    if (error instanceof ZedError || isSystemError(error)) {
      stderr.write(`zed: ${error.message}\n`);
      return 1;
    }
    throw error;
  } finally {
    signals.off("SIGINT", onInterrupt);
  }
  return 0;
}

function invokedDirectly() {
  try {
    return fs.realpathSync(process.argv[1]) === fileURLToPath(import.meta.url);
  } catch {
    return false;
  }
}

if (invokedDirectly()) process.exitCode = await main();
