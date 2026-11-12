# JournalRoller

A standalone Windows user-mode utility that advances the NTFS USN Change Journal's `FirstUSN` past the highest record referencing a target filename, evicting that filename's records from the journal without deleting the journal, resetting its `UsnJournalID`, or triggering standard deletejournal-detection heuristics.

---

## Overview

The NTFS USN Change Journal is a per-volume circular log of every file system operation, and it is a primary artifact for forensic timeline reconstruction, EDR file-tracing, and integrity checks. Because it is a ring buffer, records are only evicted when `FirstUSN` advances — a process normally driven by journal `MaximumSize` pressure that can take weeks on a lightly-loaded volume.

The conventional approach — `fsutil usn deletejournal` — is trivially detectable: the `UsnJournalID` changes, the `FirstUSN` / `NextUSN` gap collapses, and IR tooling flags the journal as recreated.

`JournalRoller` takes a different path. It streams every journal record from `FirstUSN` to `NextUSN`, identifies the highest matching USN for a given filename, and then drives a rename loop on two temp files to accelerate eviction until `FirstUSN` exceeds that matching USN. The journal survives, its identity is preserved, and its record for the target is gone.

The underlying technique — advancing `FirstUSN` past a target record to evict it while preserving `UsnJournalID` — has been discussed in DFIR literature for years. This repository is a minimal, single-file C reference implementation, primarily intended so that detection engineers can validate journal-anomaly detections against a real sample. It is not a novel primitive.

---

## Core Features

- **Targeted Eviction:** Only records whose `FileName` matches the target are aged out; the rest of the journal is untouched.
- **Journal ID Preservation:** The `UsnJournalID` is never modified, so heuristics that compare pre/post IDs still pass.
- **Rename-Driven Pressure:** A tight `MoveFileExW` loop on two temp files produces 4–6 USN reason bits per pair with zero data I/O, growing the journal tail faster than normal activity.
- **Live Progress Reporting:** Displays `FirstUSN`, remaining bytes, and elapsed time on each poll interval (every 800 rename pairs).
- **Dual-Mode Interface:** Interactive REPL when run bare; one-shot scriptable CLI when passed `<drive> <filename>`.
- **Privilege Auto-Elevation:** Enables `SeBackupPrivilege`, `SeRestorePrivilege`, and `SeManageVolumePrivilege` at startup.
- **Self-Cleaning:** Temp files (`usn_fast_<pid>_{a,b}.tmp`) are removed on exit.

---

## Architecture & How It Works

```
+-----------------------------+
|  JournalRoller.exe (user)   |
+-----------------------------+

   FSCTL_QUERY_USN_JOURNAL     |     FSCTL_READ_USN_JOURNAL
   (poll FirstUSN)             |     (stream records)
                               v
+-----------------------------+
|  \\.\X: Volume Handle       |
+-----------------------------+

                               v
+-----------------------------+
|      NTFS USN Journal       |
|      (circular buffer)      |
+-----------------------------+
```

### 1. Journal Scan

1. The volume is opened with `GENERIC_READ | GENERIC_WRITE` and `FILE_FLAG_BACKUP_SEMANTICS`.
2. `FSCTL_QUERY_USN_JOURNAL` retrieves `FirstUSN`, `NextUSN`, `UsnJournalID`, and `MaximumSize`.
3. `FSCTL_READ_USN_JOURNAL` streams records from `FirstUSN` to `NextUSN` in 1 MB chunks.
4. Each `USN_RECORD_V2` is examined; if `FileName` matches the target (case-insensitive), the record's USN is tracked as a candidate.
5. The highest matching USN is retained as the roll target.

### 2. Roll Acceleration

1. Two temp files `usn_fast_<pid>_a.tmp` and `usn_fast_<pid>_b.tmp` are created in `%TEMP%`.
2. A loop of 400 `MoveFileExW(a→b)` / `MoveFileExW(b→a)` pairs emits a burst of USN records into the journal tail.
3. `FSCTL_QUERY_USN_JOURNAL` is re-issued; if `FirstUSN` still precedes the target's highest USN, the loop repeats.
4. When `FirstUSN > highestMatchingUSN`, all records referencing the target are evicted.
5. `UsnJournalID` is re-queried and confirmed unchanged.

---

## Coverage Matrix

Utility | Query Vector | Interception Point | Result
---|---|---|---
**`fsutil usn readjournal`** | Journal enumeration | `FSCTL_READ_USN_JOURNAL` | Target absent
**`fsutil usn queryjournal`** | Journal metadata | `FSCTL_QUERY_USN_JOURNAL` | Same `UsnJournalID`, advanced `FirstUSN`
**Voidtools Everything (re-index)** | Raw MFT + USN stream | Journal read | Target absent from USN stream
**Forensic timeline tools** | Journal parse | Record stream | Target absent
**Journal-identity checks** | `UsnJournalID` comparison | Metadata | Pass (unchanged)

*Note: The tool does not touch `$MFT`, `$LogFile`, `$Secure`, Prefetch, AmCache, ShimCache, or VSS snapshots. The file's presence may still be provable through other artifacts.*

---

## Detection & OPSEC Notes

This tool bypasses deletejournal-detection heuristics, but it is not invisible. The following signals remain observable to defenders with appropriate telemetry:

- **Rename-rate spike on two files:** 800 rename pairs per iteration produces a distinct `USN_REASON_RENAME_OLD_NAME` / `RENAME_NEW_NAME` burst.
- **`FirstUSN` jump without matching `NextUSN` growth:** A multi-MB `FirstUSN` advance with modest `NextUSN` growth is anomalous.
- **`%TEMP%\usn_fast_<pid>_*.tmp`:** Fixed naming pattern; trivially YARA-able.
- **Raw volume handle:** `\\.\C:` opened with `GENERIC_WRITE` by a non-`fsutil` / non-`chkdsk` process is a strong EDR signal.
- **`FSCTL_*` ioctl ETW:** The `Microsoft-Windows-Ntfs` ETW provider logs `DeviceIoControl` against NTFS if enabled.

Defenders should pair USN monitoring with `Microsoft-Windows-Kernel-File` ETW, Sysmon, and `$LogFile` parsing, none of which this tool modifies.

---

## Target Configuration

The target filename and drive letter are supplied at runtime:

  * **CLI mode:** `JournalRoller.exe C: target.exe`
  * **Interactive mode:** prompted on startup; `exit` or `q` to quit.

---

## Building

### Requirements

  * Visual Studio 2019/2022 (or MinGW-w64 cross-compiler)
  * Windows SDK (`kernel32.lib`, `advapi32.lib`)

### Build Instructions

MSVC (x64 Native Tools Command Prompt):

    cl /O2 /W3 /utf-8 /EHsc JournalRoller.c /link advapi32.lib kernel32.lib

MinGW-w64 (from Linux):

    x86_64-w64-mingw32-gcc -O2 -municode -static JournalRoller.c -o JournalRoller.exe -ladvapi32

---

## Usage

### CLI

    :: Roll a filename out of the C: journal
    JournalRoller.exe C: payload.exe

    :: Roll out of D:
    JournalRoller.exe D: invoice.pdf

### Interactive

    > JournalRoller.exe
    [?] Enter filename to roll out (or 'exit'):

### Verifying

    :: Should return no matches for the rolled filename
    fsutil usn readjournal C: | findstr /i payload.exe

    :: Journal must still exist with the same UsnJournalID
    fsutil usn queryjournal C:

---

## Limitations

  * NTFS only. ReFS, FAT, exFAT, and network shares are unsupported.
  * Requires Administrator (`SE_MANAGE_VOLUME_NAME`).
  * Journal must be active on the target volume.
  * VSS snapshots and other artifacts (`$MFT`, `$LogFile`, Event Logs, EDR telemetry) are not modified.
  * Match is filename-only; use `FileReferenceNumber` for path-precise matching.

---

## License

This project is licensed under the MIT License.