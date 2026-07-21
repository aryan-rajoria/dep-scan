# PyInstaller runtime hook for depscan macOS SEA builds.
#
# The bundled cdxgen SEA is a Node.js Single Executable Application whose
# Mach-O layout (node binary + postject-injected blob) trips codesign with
# "internal error in Code Signing subsystem" when PyInstaller tries to
# re-sign it during build. To work around this, the macOS build workflow
# zeroes cdxgen's first 4 bytes (the Mach-O magic number) so PyInstaller's
# Mach-O auto-detection skips the file entirely.
#
# This hook runs at frozen-binary startup (before depscan's main entry
# point) and restores the original Mach-O 64-bit magic so the bundled
# cdxgen can exec. Without this restoration, the kernel would reject the
# exec with EBADARCH (arm64) or the binary would silently fail (amd64).
#
# The restoration is idempotent: if the magic bytes are already correct
# (e.g., on Linux/Windows where no disguise is applied, or on a re-run),
# the hook does nothing.

import os
import sys

# Mach-O 64-bit magic, little-endian. Covers both arm64 and x86_64 thin
# (single-arch) executables, which is what cdxgen ships per arch.
MACHO_MAGIC_64_LE = b'\xcf\xfa\xed\xfe'


def _restore_cdxgen_magic():
    if sys.platform != 'darwin':
        return
    meipass = getattr(sys, '_MEIPASS', None)
    if not meipass:
        return
    cdxgen_path = os.path.join(meipass, 'local_bin', 'cdxgen')
    if not os.path.exists(cdxgen_path):
        return
    try:
        with open(cdxgen_path, 'r+b') as f:
            magic = f.read(4)
            if magic == b'\x00\x00\x00\x00':
                f.seek(0)
                f.write(MACHO_MAGIC_64_LE)
        # Defensive: ensure the exec bit is set. PyInstaller preserves file
        # mode for --add-data in most cases, but some tempdir filesystems
        # do not retain the bit on extraction. find_cdxgen_cmd() in
        # xbom_lib/cdxgen.py also does this, but the restoration write
        # above may have reset it on some filesystems.
        mode = os.stat(cdxgen_path).st_mode
        if not (mode & 0o111):
            os.chmod(cdxgen_path, mode | 0o755)
    except OSError:
        # If we can't restore the magic, depscan's find_cdxgen_cmd() will
        # fail later with a clearer error. Don't crash at startup.
        pass


_restore_cdxgen_magic()
