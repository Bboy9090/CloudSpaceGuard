#!/usr/bin/env bash
# build_appimage.sh — AppDir and AppImage packager for CloudSpaceGuard
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "${SCRIPT_DIR}/../.." && pwd)"
DIST_DIR="${ROOT_DIR}/dist_linux"
APPDIR="${DIST_DIR}/CloudSpaceGuard.AppDir"

echo "==> Building Linux Package Structure for Cloud Space Guard..."
rm -rf "${APPDIR}"
mkdir -p "${APPDIR}/usr/bin"
mkdir -p "${APPDIR}/usr/share/applications"
mkdir -p "${APPDIR}/usr/share/icons/hicolor/scalable/apps"
mkdir -p "${APPDIR}/usr/lib/cloud-space-guard/web"

# Copy core engine & web bundle
cp "${ROOT_DIR}/space_guard_agent.py" "${APPDIR}/usr/lib/cloud-space-guard/"
cp -R "${ROOT_DIR}/web/"* "${APPDIR}/usr/lib/cloud-space-guard/web/"
cp "${SCRIPT_DIR}/com.cloudspaceguard.desktop.desktop" "${APPDIR}/usr/share/applications/"
cp "${SCRIPT_DIR}/com.cloudspaceguard.desktop.desktop" "${APPDIR}/"
cp "${ROOT_DIR}/store_packaging/cloud_space_guard_icon.svg" "${APPDIR}/usr/share/icons/hicolor/scalable/apps/cloud-space-guard.svg"
cp "${ROOT_DIR}/store_packaging/cloud_space_guard_icon.svg" "${APPDIR}/cloud-space-guard.svg"
cp "${ROOT_DIR}/store_packaging/cloud_space_guard_icon.svg" "${APPDIR}/.DirIcon"

# AppRun launcher script
cat << 'EOF' > "${APPDIR}/AppRun"
#!/usr/bin/env bash
HERE="$(dirname "$(readlink -f "${0}")")"
export PATH="${HERE}/usr/bin:${PATH}"
export PYTHONPATH="${HERE}/usr/lib/cloud-space-guard:${PYTHONPATH:-}"

# Check for Python 3 runtime on host
if ! command -v python3 >/dev/null 2>&1; then
    echo "Error: python3 is required to run Cloud Space Guard." >&2
    exit 1
fi

exec python3 "${HERE}/usr/lib/cloud-space-guard/space_guard_agent.py" serve "$@"
EOF
chmod +x "${APPDIR}/AppRun"

# Wrapper binary in /usr/bin
cat << 'EOF' > "${APPDIR}/usr/bin/cloud-space-guard"
#!/usr/bin/env bash
exec /usr/bin/env python3 /usr/lib/cloud-space-guard/space_guard_agent.py serve "$@"
EOF
chmod +x "${APPDIR}/usr/bin/cloud-space-guard"

# Package tar.gz portable bundle
cd "${DIST_DIR}"
tar -czf "CloudSpaceGuard-Linux-Universal.tar.gz" -C "${DIST_DIR}" "CloudSpaceGuard.AppDir"
echo "[✓] Linux Universal AppDir and CloudSpaceGuard-Linux-Universal.tar.gz created in ${DIST_DIR}"
