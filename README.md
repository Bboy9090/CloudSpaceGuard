# Cloud Space Guard — Verified Local Vault Copy & System Cache Cleaner

Cross-platform local vault copy and system cache inspection suite for **macOS, Windows, Linux, and ChromeOS (Chromebooks)**.

> **Data Safety Notice**:
> Copying a file or folder into a local sync folder (such as Google Drive, OneDrive, or iCloud) verifies the local copy's checksum and creates a receipt, but **does not confirm remote cloud durability or upload completion**. To prevent accidental data loss, **original sources are retained**. Because sources are kept, vault copying **does not reclaim disk space**.

## Key Capabilities

1. **Space Target Planner**: Set your target free space (e.g., `74 GB` for Bootcamp or VMs) and inspect live disk telemetry.
2. **Verified Local Vault Copying**:
   - Computes local **SHA-256** checksums and creates collision-isolated vault copies in unique destination directories.
   - Retains original source files intact.
   - Rejects special files and symlinks. Includes every supported regular file when archiving directory trees.
   - Verifies complete archive members against pre-copy snapshots and detects concurrent modifications.
   - Leaves a `.cloudstub` JSON receipt recording source, vault destination, and checksum.
3. **Safe, Overwrite-Protected Restore**:
   - Restores exclusively into absent destinations; refuses to overwrite existing files, directories, or symlinks.
   - Stages directory archive extractions in temporary directories and validates all archive paths against path traversal before moving into place.
4. **System Cache Cleaner (Individual Review)**:
   - Detects regenerable developer and application caches (`~/.npm`, `~/Library/Caches/Google`, `~/.cargo/registry`, `Xcode/DerivedData`, Homebrew, pip).
   - Each cache can be reviewed and cleared individually. Bulk cleaning is disabled pending safety review.

## Quick Start

### Launch the Web Dashboard (macOS / Linux / Chromebook)
```bash
./start-macos-linux-chromeos.sh
```
Then open **http://127.0.0.1:7474**.

### Launch on Windows
Double-click `start-windows.bat` or run:
```powershell
python space_guard_agent.py serve --port 7474
```

### CLI Commands
```bash
# View live disk telemetry and detected local cloud vault paths
python3 space_guard_agent.py status --target-gb 74

# Scan system caches and large local files/folders
python3 space_guard_agent.py scan --min-mb 25

# Create a verified local vault copy (original retained; no space reclaimed)
python3 space_guard_agent.py offload --file ~/Projects/MyProject --provider gdrive

# Restore an item from its .cloudstub receipt into an absent destination
python3 space_guard_agent.py restore --stub ~/Projects/MyProject.cloudstub

# Safely purge a specific regenerable developer cache by ID
python3 space_guard_agent.py clean-cache --id cargo_cache
```
