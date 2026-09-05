# HashSnap

A multi-threaded MD5 / SHA-1 / SHA-256 / SHA-512 / NTLM hash cracker
written in C. Supports dictionary attacks (with a rule-based mutation
engine), brute-force attacks, salted hashes, and **batch mode** —
crack an entire file of leaked/dumped hashes in a single pass. All
hash algorithms are implemented from scratch (no OpenSSL or other
crypto library dependency) — pure C, POSIX threads only.

## ⚠️ Authorized use only

This tool is for **educational purposes and authorized security testing
only** — e.g. auditing the strength of your own passwords/hashes, or
systems you have explicit written permission to test. Do not use it
against hashes or accounts you don't own or lack authorization to test.

## Features

- **Hash algorithms**: MD5, SHA-1, SHA-256, SHA-512, and **NTLM**
  (the Windows/Active Directory password hash format,
  `MD4(UTF-16LE(password))`) — all implemented from the published
  specifications and verified against known test vectors.
- **Batch mode**: point it at a file of `identifier:hash` (or
  `identifier:hash:salt`) lines — like a dumped `/etc/shadow`-style
  list, an NTLM dump from `secretsdump.py`, or a leaked user table —
  and crack all of them in one pass over your wordlist/keyspace.
  When every hash shares the same salt (or has no salt), a hash table
  is used so each candidate is hashed once and checked against every
  target in O(1) average time, instead of once per target.
- **Salted hashes**: `-s <salt>` for a single global salt applied to
  every target, or a per-row salt column in a batch file (mixed salts
  per row are supported — each is a real per-target check).
  `--salt-mode prefix|suffix` controls whether the salt is prepended
  or appended.
- **Rule-based mutation engine** (`-r`): for each dictionary word, also
  tries common real-world variants — capitalization, all-caps, leetspeak
  (`a→4`, `e→3`, `i→1`, `o→0`, `s→5`), and common suffixes (`1`, `123`,
  `!`, years, etc.), including combined patterns like `Password1`.
- **Brute-force attack**: exhaustive search over a configurable character
  set and length range (single-hash mode).
- **Result output** (`-o <file>`): writes `identifier:plaintext` for
  each cracked hash as it's found — useful for feeding into other
  tooling or just keeping a record.
- **Multi-threaded**, with live progress reporting (cracked/total,
  candidates tried, hashes/sec, elapsed time).

## Build

Requires `gcc` and `pthread` (any modern Linux/macOS/WSL environment).

```bash
make
```

This produces a single `hashsnap` binary.

## Usage

### Single hash, dictionary mode

```bash
./hashsnap -h <hash_hex> -t <type> -w <wordlist_file> [-r] [-j threads]
```

### Single hash, brute-force mode

```bash
./hashsnap -h <hash_hex> -t <type> -b -c <charset> --min <n> --max <n> [-j threads]
```

### Batch mode — crack many hashes in one pass

```bash
./hashsnap --batch <file> -t <type> -w <wordlist_file> [-r] [-j threads] [-o <outfile>]
```

**Batch file format** — one target per line:

```
alice:5f4dcc3b5aa765d61d8327deb882cf99
bob:e10adc3949ba59abbe56e057f20f883e
```

or, with a per-row salt (3rd field):

```
alice:472652e632d95c0e2d59f9281a66356e8da9463b33fc0209fbacb4befc5a431b:pepper42
bob:fdc891dbe488c371db8f42b652bfc9e1f0a0c6a68ad0858249873952769c562c:pepper42
```

A bare hash with no `identifier:` prefix is also accepted (it's
labeled `line<N>` in output).

### Options

| Flag | Description |
|---|---|
| `-h <hash>` | Target hash, in hex (single-hash mode) |
| `--batch <file>` | Batch file of targets (see format above) |
| `-t <type>` | `md5`, `sha1`, `sha256`, `sha512`, or `ntlm` |
| `-w <file>` | Wordlist file (dictionary mode) |
| `-r` | Apply the mutation rule engine to each dictionary word |
| `-b` | Enable brute-force mode (single-hash mode only) |
| `-c <charset>` | Character set for brute-force, e.g. `"abcdefghijklmnopqrstuvwxyz0123456789"` |
| `--min <n>` | Minimum candidate length for brute-force (default 1) |
| `--max <n>` | Maximum candidate length for brute-force (default 6) |
| `-s <salt>` | Global salt (literal text) applied to every target that doesn't have its own |
| `--salt-mode <m>` | `prefix` (`salt+candidate`) or `suffix` (`candidate+salt`). Default: `prefix` |
| `-o <file>` | Write cracked results here as `identifier:plaintext` |
| `-j <n>` | Number of worker threads (default 4) |
| `--help` | Show usage |

## Examples

Crack a single MD5 hash, trying mutated variants too:

```bash
./hashsnap -h 5f4dcc3b5aa765d61d8327deb882cf99 -t md5 -w data/sample_wordlist.txt -r
```

Crack a batch of NTLM hashes (e.g. dumped from a Windows domain
controller) in one pass, saving results to a file:

```bash
./hashsnap --batch data/sample_ntlm_batch.txt -t ntlm -w data/sample_wordlist.txt -r -o cracked.txt
```

Crack a batch of salted SHA-256 hashes that all share one salt (read
from the batch file's third column):

```bash
./hashsnap --batch data/sample_salted_hashes.txt -t sha256 -w data/sample_wordlist.txt -r --salt-mode prefix
```

Brute-force a short SHA-1 hash over lowercase letters + digits, 1–5
characters, using 8 threads:

```bash
./hashsnap -h aaf4c61ddcc5e8a2dabede0f3b482cd9aea9434d -t sha1 -b \
  -c "abcdefghijklmnopqrstuvwxyz0123456789" --min 1 --max 5 -j 8
```

### Sample output (batch mode)

Output is colorized in a real terminal (auto-disabled when piped or
redirected, or with `NO_COLOR=1`):

```
 _               _
| |             | |
| |__   __ _ ___| |__  ___ _ __   __ _ _ __
| '_ \ / _` / __| '_ \/ __| '_ \ / _` | '_ \
| | | | (_| \__ \ | | \__ \ | | | (_| | |_) |
|_| |_|\__,_|___/_| |_|___/_| |_|\__,_| .__/
                                      | |
                                      |_|
crack hashes fast. dictionary + rules + brute-force + batch.

[!] For authorized security testing and educational use only.

Hash type : ntlm
Targets   : 5 (batch: data/sample_ntlm_batch.txt)
Mode      : dictionary
Threads   : 4
Wordlist  : data/sample_wordlist.txt (20 words)
-----------------------------------------------------
-----------------------------------------------------
[+] CRACKED user1                          -> password
[+] CRACKED user3                          -> dragon
[+] CRACKED user5                          -> sunshine
[+] CRACKED user2                          -> admin
[*]      4/5      cracked |         20 candidates |         40 H/s |    0.5s
-----------------------------------------------------
[*] Cracked 4 / 5 hashes.
[*] Results written to cracked.txt
[*] Total attempts : 20
[*] Time elapsed   : 0.50s
[*] Average rate   : 40 H/s
=====================================================
```

Note the attempt count: only 20 candidates were tried total (the
wordlist size, since rules weren't used here) to crack 4 of the 5
hashes — not 20 × 5. That's the batch hash-table lookup at work.

## How it works

- **Hashing**: `src/md5.c`, `src/sha1.c`, `src/sha256.c`, `src/sha512.c`
  are self-contained implementations of each algorithm's block-processing
  and padding logic. `src/md4.c` implements MD4, and `src/ntlm.c` wraps
  it to produce NTLM hashes (`MD4` over the password re-encoded as
  UTF-16LE) — no external crypto library required anywhere.
- **Batch matching**: all targets are loaded into a `target_t` array.
  If every target shares the same salt (including the common
  no-salt-at-all case), a separate-chaining hash table keyed on the
  first 8 bytes of each target digest is built once up front, so each
  candidate is hashed a single time and checked against all targets in
  O(1) average time. If salts differ per row, the tool falls back to
  checking each candidate against every still-uncracked target
  individually — this is inherent to how salts work: they're
  specifically designed to prevent this kind of shared precomputation
  across accounts, so a "slow path" here is the cryptographically
  correct behavior, not a missed optimization.
- **Dictionary mode**: the wordlist is loaded into memory once; each
  thread atomically claims the next unprocessed word (via a
  mutex-guarded index) until the list is exhausted or every target is
  cracked.
- **Rules engine** (`src/rules.c`): generates a fixed set of mutations
  per word — capitalization, case changes, leetspeak substitution, and
  suffix/combined-suffix variants — modeled on patterns commonly seen
  in real-world password reuse (e.g. `hunter2` → `Hunter2`,
  `hunter2023`).
- **Brute-force mode**: candidates are generated on the fly by treating
  the candidate space as a mixed-radix number system over the charset;
  each thread is assigned a distinct stride so no synchronization is
  needed except when reporting a match. (Not yet wired up to batch
  mode — see "Possible extensions".)
- **Threading**: a shared `remaining` counter (targets not yet cracked)
  is checked by all worker threads to stop promptly once every target
  in the job is found, or the wordlist/keyspace is exhausted.

## Project structure

```
hashsnap/
├── Makefile
├── README.md
├── include/
│   ├── cracker.h
│   ├── colors.h
│   ├── md5.h
│   ├── md4.h
│   ├── ntlm.h
│   ├── sha1.h
│   ├── sha256.h
│   ├── sha512.h
│   └── rules.h
├── src/
│   ├── main.c        # CLI parsing, batch/target loading, orchestration
│   ├── cracker.c      # threading, salting, hash-table matching logic
│   ├── rules.c        # mutation rule engine
│   ├── colors.c       # terminal color detection (NO_COLOR aware)
│   ├── md5.c
│   ├── md4.c
│   ├── ntlm.c
│   ├── sha1.c
│   ├── sha256.c
│   └── sha512.c
└── data/
    ├── sample_wordlist.txt
    ├── sample_ntlm_batch.txt        # unsalted batch demo
    └── sample_salted_hashes.txt     # uniform-salt batch demo
```

## Possible extensions

- Brute-force mode for batch targets (currently dictionary-only)
- bcrypt/scrypt/Argon2 support (adaptive KDFs — would need iteration
  count handling, unlike the fixed-cost hashes here)
- GPU acceleration (OpenCL/CUDA) for brute-force mode
- Resume/checkpoint support for long-running jobs
- Rule files loaded from disk (Hashcat-style `.rule` syntax) instead of
  the built-in fixed rule set
- Auto-detect hash type from hash length/format
