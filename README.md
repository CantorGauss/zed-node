# Zed for Node.js

A read-only tool for listing and extracting password-protected `.zed` archives. It is a port of the Python `zed.py` CLI with the same behaviour and safety checks. It never modifies the archive and refuses to overwrite existing files.

## Requirements

Node.js 18.3 or newer (tested with Node.js 26). There are no npm dependencies: AES, PBKDF2 and zlib come from Node's built-in modules.

## Usage

```sh
node zed.js archive.zed --list
node zed.js archive.zed -o output_directory
```

The password is read from the terminal without echo; it is never accepted as a command-line argument. When input is piped, the first line is used as the password. Ctrl-C stops the extraction and removes the partially written file.

Running `npm install -g .` in this directory also installs a `zed` command.

## Library

```js
import { ZedArchive } from "./zed.js";

const archive = new ZedArchive("archive.zed", password);
for (const [entry, relativePath] of archive.names()) console.log(relativePath, entry.size);
await archive.extractTo("output_directory", { progress: (done, total, file) => {} });
```

Opening the archive and listing it are synchronous. Reading files (`read`, `iterRead`, `extractTo`) is asynchronous, because files are decompressed as a stream: memory use stays bounded and output stops as soon as it exceeds the size recorded in the catalog. Errors caused by the archive are thrown as `ZedError`.

## Supported formats and limitations

The tool supports `passworduser` entries, AES-CBC-STREAM and AES-CBC-CTS (CBC-CS3), PBKDF2-SHA-256, and the PKCS#12 SHA-1/SHA-256 key derivation described in the [Zed format documentation](https://www.beuc.net/zed/zed.md). Certificate-based `rsauser` entries are not supported.

Archives that contain duplicate paths are refused. The comparison ignores case and Unicode normalization, as on Windows and macOS.

## Tests

The tests use the published format vectors and small archives built in memory. No private archive or password is included:

```sh
npm test
```
