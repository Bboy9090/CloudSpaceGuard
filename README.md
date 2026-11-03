# Cloud Space Guard — All-For-One Multi-Cloud Space Saver

Cross-platform disk space recovery and cryptographic cloud offload suite for **macOS, Windows, Linux, and ChromeOS (Chromebooks)**.

## Key Capabilities

1. **Smart Space Target Planner**: Set your target free space (e.g., `74 GB` for Bootcamp or VMs) and track live disk deficit and reclaimable space.
2. **Verify-Before-Delete Cloud Offload**:
   - Computes local **SHA-256** checksums before moving files or archived project snapshots.
   - Supports **Google Drive**, **Apple iCloud Drive** (including native `brctl evict` on macOS), **Microsoft OneDrive**, **Dropbox**, and **3rd-Party Cloud Containers** (AWS S3, Cloudflare R2, Backblaze B2, Wasabi, WebDAV, `rclone`).
   - Leaves a lightweight `.cloudstub` JSON receipt behind for 1-click verified restore.
3. **System Cache & Project Build Cleaner**:
   - Detects and cleans regenerable developer and browser caches (`~/Projects/*/src-tauri/target`, `node_modules`, `~/.npm`, `~/Library/Caches/Google`, `~/.cargo`, `Xcode/DerivedData`, `ms-playwright`, `pnpm`, Docker).

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
# View live disk telemetry and connected cloud mounts
python3 space_guard_agent.py status --target-gb 74

# Scan system caches and large offloadable files/projects
python3 space_guard_agent.py scan --min-mb 25

# Verify SHA-256 and offload a file or project folder to Google Drive or iCloud Drive
python3 space_guard_agent.py offload --file ~/Projects/BobFWTools-probe-241 --provider gdrive

# Restore an offloaded item from its .cloudstub receipt
python3 space_guard_agent.py restore --stub ~/Projects/BobFWTools-probe-241.cloudstub

# Safely purge regenerable build caches
python3 space_guard_agent.py clean-cache --id projects_rust_targets
```
