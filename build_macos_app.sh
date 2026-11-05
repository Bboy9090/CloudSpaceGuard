#!/bin/zsh
set -e

CSG_DIR="$(cd "$(dirname "$0")" && pwd)"
APP_NAME="CloudSpaceGuard"
APP_BUNDLE="${CSG_DIR}/${APP_NAME}.app"
CONTENTS_DIR="${APP_BUNDLE}/Contents"
MACOS_DIR="${CONTENTS_DIR}/MacOS"
RESOURCES_DIR="${CONTENTS_DIR}/Resources"

rm -rf "${APP_BUNDLE}"
mkdir -p "${MACOS_DIR}" "${RESOURCES_DIR}"

echo "[1/5] Generating Store-Compliant Info.plist & PrivacyInfo.xcprivacy..."
cat > "${CONTENTS_DIR}/Info.plist" <<EOF
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>CFBundleDevelopmentRegion</key>
    <string>en</string>
    <key>CFBundleExecutable</key>
    <string>${APP_NAME}</string>
    <key>CFBundleIconFile</key>
    <string>AppIcon</string>
    <key>CFBundleIdentifier</key>
    <string>com.cloudspaceguard.desktop</string>
    <key>CFBundleInfoDictionaryVersion</key>
    <string>6.0</string>
    <key>CFBundleName</key>
    <string>Cloud Space Guard</string>
    <key>CFBundleDisplayName</key>
    <string>Cloud Space Guard</string>
    <key>CFBundlePackageType</key>
    <string>APPL</string>
    <key>CFBundleShortVersionString</key>
    <string>1.1.0</string>
    <key>CFBundleVersion</key>
    <string>110</string>
    <key>LSApplicationCategoryType</key>
    <string>public.app-category.utilities</string>
    <key>LSMinimumSystemVersion</key>
    <string>13.0</string>
    <key>NSHighResolutionCapable</key>
    <true/>
    <key>ITSAppUsesNonExemptEncryption</key>
    <false/>
    <key>NSHumanReadableCopyright</key>
    <string>Copyright © 2026 Bobby Blanco. All rights reserved.</string>
</dict>
</plist>
EOF

cp "${CSG_DIR}/store_packaging/macos/PrivacyInfo.xcprivacy" "${RESOURCES_DIR}/PrivacyInfo.xcprivacy"
plutil -lint "${CONTENTS_DIR}/Info.plist"
plutil -lint "${RESOURCES_DIR}/PrivacyInfo.xcprivacy"

echo "[2/5] Installing AppIcon.icns from store_packaging/macos/AppIcon.icns..."
if [ -f "${CSG_DIR}/store_packaging/macos/AppIcon.icns" ]; then
    cp "${CSG_DIR}/store_packaging/macos/AppIcon.icns" "${RESOURCES_DIR}/AppIcon.icns"
else
    python3 "${CSG_DIR}/generate_store_assets.py"
    cp "${CSG_DIR}/store_packaging/macos/AppIcon.icns" "${RESOURCES_DIR}/AppIcon.icns"
fi

echo "[3/5] Bundling Offline Web UI & Python Agent into Contents/Resources..."
cp "${CSG_DIR}/space_guard_agent.py" "${RESOURCES_DIR}/space_guard_agent.py"
cp -R "${CSG_DIR}/web" "${RESOURCES_DIR}/web"

echo "[4/5] Compiling Native macOS Swift + WKWebView Wrapper Binary..."
cat > "${CSG_DIR}/MacMain.swift" <<'SWIFT_MAIN'
import AppKit
import WebKit

class AppDelegate: NSObject, NSApplicationDelegate {
    var window: NSWindow!
    var webView: WKWebView!
    var backendProcess: Process?

    func applicationDidFinishLaunching(_ notification: Notification) {
        startBackendIfNeeded()

        let rect = NSRect(x: 0, y: 0, width: 1240, height: 820)
        window = NSWindow(
            contentRect: rect,
            styleMask: [.titled, .closable, .miniaturizable, .resizable],
            backing: .buffered,
            defer: false
        )
        window.center()
        window.title = "Cloud Space Guard — Multi-Cloud Offload & Space Saver"

        let config = WKWebViewConfiguration()
        webView = WKWebView(frame: rect, configuration: config)
        window.contentView = webView
        window.makeKeyAndOrderFront(nil)

        setupMenu()

        loadLocalDashboardWhenReady(attempt: 0)
    }

    func loadLocalDashboardWhenReady(attempt: Int) {
        guard let url = URL(string: "http://127.0.0.1:7474/") else { return }
        if attempt >= 20 {
            let html = """
            <html><body style="background:#0b1120;color:white;font-family:-apple-system;padding:32px">
            <h2>Cloud Space Guard backend did not start.</h2>
            <p>Quit the app, verify Python 3 is available, and relaunch.</p>
            </body></html>
            """
            webView.loadHTMLString(html, baseURL: nil)
            return
        }

        var request = URLRequest(url: url)
        request.timeoutInterval = 0.5
        URLSession.shared.dataTask(with: request) { _, response, _ in
            if let http = response as? HTTPURLResponse, http.statusCode == 200 {
                DispatchQueue.main.async {
                    self.webView.load(URLRequest(url: url))
                }
            } else {
                DispatchQueue.main.asyncAfter(deadline: .now() + 0.25) {
                    self.loadLocalDashboardWhenReady(attempt: attempt + 1)
                }
            }
        }.resume()
    }

    func setupMenu() {
        let mainMenu = NSMenu()
        let appMenuItem = NSMenuItem()
        mainMenu.addItem(appMenuItem)
        let appMenu = NSMenu()
        appMenu.addItem(withTitle: "Authorize Folder (NSOpenPanel Sandbox Grant)...", action: #selector(authorizeFolder), keyEquivalent: "o")
        appMenu.addItem(NSMenuItem.separator())
        appMenu.addItem(withTitle: "Quit Cloud Space Guard", action: #selector(NSApplication.terminate(_:)), keyEquivalent: "q")
        appMenuItem.submenu = appMenu
        NSApp.mainMenu = mainMenu
    }

    @objc func authorizeFolder() {
        let panel = NSOpenPanel()
        panel.canChooseFiles = true
        panel.canChooseDirectories = true
        panel.allowsMultipleSelection = false
        panel.prompt = "Grant Access"
        panel.message = "Select a folder or Cloud Vault to grant Cloud Space Guard read/write access."
        panel.beginSheetModal(for: window) { _ in }
    }

    func startBackendIfNeeded() {
        guard let resPath = Bundle.main.resourcePath else { return }
        let scriptPath = (resPath as NSString).appendingPathComponent("space_guard_agent.py")
        let candidates = [
            "/usr/local/bin/python3.11",
            "/opt/homebrew/bin/python3",
            "/Library/Frameworks/Python.framework/Versions/Current/bin/python3",
            "/Applications/Xcode.app/Contents/Developer/usr/bin/python3",
            "/usr/bin/python3"
        ]
        guard let pyBin = candidates.first(where: { FileManager.default.isExecutableFile(atPath: $0) }) else { return }
        let proc = Process()
        proc.executableURL = URL(fileURLWithPath: pyBin)
        proc.arguments = [scriptPath, "serve", "--port", "7474"]
        try? proc.run()
        backendProcess = proc
    }

    func applicationWillTerminate(_ notification: Notification) {
        backendProcess?.terminate()
    }

    func applicationShouldTerminateAfterLastWindowClosed(_ sender: NSApplication) -> Bool {
        return true
    }
}

let app = NSApplication.shared
let delegate = AppDelegate()
app.delegate = delegate
app.setActivationPolicy(.regular)
app.activate(ignoringOtherApps: true)
app.run()
SWIFT_MAIN

swiftc -O -target x86_64-apple-macos13.0 "${CSG_DIR}/MacMain.swift" -framework AppKit -framework WebKit -o "${MACOS_DIR}/${APP_NAME}_x86_64"
swiftc -O -target arm64-apple-macos13.0 "${CSG_DIR}/MacMain.swift" -framework AppKit -framework WebKit -o "${MACOS_DIR}/${APP_NAME}_arm64"
lipo -create -output "${MACOS_DIR}/${APP_NAME}" "${MACOS_DIR}/${APP_NAME}_x86_64" "${MACOS_DIR}/${APP_NAME}_arm64"
rm -f "${MACOS_DIR}/${APP_NAME}_x86_64" "${MACOS_DIR}/${APP_NAME}_arm64" "${CSG_DIR}/MacMain.swift"

echo "[5/5] Code-signing CloudSpaceGuard.app with Hardened Runtime + Desktop Entitlements..."
cat > "${CSG_DIR}/store_packaging/macos/entitlements.desktop.plist" <<EOF
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>com.apple.security.files.user-selected.read-write</key>
    <true/>
    <key>com.apple.security.network.client</key>
    <true/>
    <key>com.apple.security.network.server</key>
    <true/>
</dict>
</plist>
EOF
codesign --force --deep --options runtime --entitlements "${CSG_DIR}/store_packaging/macos/entitlements.desktop.plist" --sign - "${APP_BUNDLE}"
codesign --verify --deep --strict --verbose=2 "${APP_BUNDLE}"
rm -rf "/Applications/${APP_NAME}.app"
cp -R "${APP_BUNDLE}" "/Applications/${APP_NAME}.app"

echo "✓ Built and verified native macOS bundle: ${APP_BUNDLE} and /Applications/${APP_NAME}.app"
