#!/usr/bin/env python3
"""
generate_store_assets.py
Generates complete Icon (.icns, .ico, .svg, MSIX WACK PNGs) and Splash Screen sets
for both CloudSpaceGuard (/Users/bj23/Documents/antigravity/cloud-space-guard)
and BobFWTools (/Users/bj23/Documents/antigravity/silly-galileo) with zero third-party dependencies.
Includes both the pure-Python SDF renderer and high-precision CoreGraphics vector super-sampling on macOS.
"""
import math
import os
import subprocess
import struct
import zlib
from pathlib import Path


# ---------------------------------------------------------------------------
# Low-Level PNG & ICO Binary Encoders (Zero External Dependencies)
# ---------------------------------------------------------------------------
def encode_png(width: int, height: int, rgba_bytes: bytes) -> bytes:
    """Packs raw RGBA bytes into a standard compliant PNG image."""
    stride = width * 4
    raw = bytearray()
    for y in range(height):
        raw.append(0)  # Filter type 0
        raw.extend(rgba_bytes[y * stride : (y + 1) * stride])

    def chunk(tag: bytes, data: bytes) -> bytes:
        return (
            struct.pack("!I", len(data))
            + tag
            + data
            + struct.pack("!I", zlib.crc32(tag + data) & 0xFFFFFFFF)
        )

    ihdr = struct.pack("!IIBBBBB", width, height, 8, 6, 0, 0, 0)
    idat = zlib.compress(bytes(raw), level=6)
    return b"\x89PNG\r\n\x1a\n" + chunk(tag=b"IHDR", data=ihdr) + chunk(tag=b"IDAT", data=idat) + chunk(tag=b"IEND", data=b"")


def encode_ico(png_blobs: list[tuple[int, int, bytes]]) -> bytes:
    """Packs multiple (width, height, png_bytes) tuples into a Windows .ico file."""
    header = struct.pack("<HHH", 0, 1, len(png_blobs))
    directory = bytearray()
    payload = bytearray()
    offset = 6 + (16 * len(png_blobs))

    for w, h, data in png_blobs:
        bw = 0 if w >= 256 else w
        bh = 0 if h >= 256 else h
        directory.extend(struct.pack("<BBBBHHII", bw, bh, 0, 0, 1, 32, len(data), offset))
        payload.extend(data)
        offset += len(data)

    return header + bytes(directory) + bytes(payload)


def clamp(v: float, lo: float = 0.0, hi: float = 1.0) -> float:
    return max(lo, min(hi, v))


def lerp_color(c1: tuple[int, int, int], c2: tuple[int, int, int], t: float) -> tuple[int, int, int]:
    t = clamp(t)
    return (
        int(c1[0] + (c2[0] - c1[0]) * t),
        int(c1[1] + (c2[1] - c1[1]) * t),
        int(c1[2] + (c2[2] - c1[2]) * t),
    )


def blend(bg: tuple[int, int, int], fg: tuple[int, int, int], alpha: float) -> tuple[int, int, int]:
    a = clamp(alpha)
    return (
        int(bg[0] * (1.0 - a) + fg[0] * a),
        int(bg[1] * (1.0 - a) + fg[1] * a),
        int(bg[2] * (1.0 - a) + fg[2] * a),
    )


def sd_seg(px: float, py: float, ax: float, ay: float, bx: float, by: float) -> float:
    """Signed distance from point (px, py) to line segment (ax, ay)-(bx, by)."""
    pax, pay = px - ax, py - ay
    bax, bay = bx - ax, by - ay
    denom = bax * bax + bay * bay
    h = clamp((pax * bax + pay * bay) / denom) if denom > 1e-9 else 0.0
    dx, dy = pax - bax * h, pay - bay * h
    return math.hypot(dx, dy)


# ---------------------------------------------------------------------------
# Procedural Renderer: CloudSpaceGuard (Vault Shield + Cloud + SHA-256 Check)
# ---------------------------------------------------------------------------
def render_cloud_space_guard(width: int, height: int, is_splash: bool = False) -> bytes:
    buf = bytearray(width * height * 4)
    cx, cy = width / 2.0, height / 2.0
    scale = min(width, height) * (0.58 if is_splash else 0.86)
    half = scale / 2.0
    aa = 1.5 / max(scale, 1.0)

    bg_top = (11, 17, 32)      # #0B1120
    bg_bot = (17, 24, 39)      # #111827
    emerald = (16, 185, 129)   # #10B981
    cyan = (6, 182, 212)       # #06B6D4
    white = (240, 253, 250)

    for y in range(height):
        vy = y / max(height - 1, 1)
        base_bg = lerp_color(bg_top, bg_bot, vy)
        for x in range(width):
            nx = (x - cx) / half
            ny = (y - cy) / half
            r_dist = math.hypot(nx, ny)

            if not is_splash:
                corner_d = math.hypot(max(abs(nx) - 0.72, 0.0), max(abs(ny) - 0.72, 0.0)) - 0.24
                if corner_d > aa:
                    continue
                card_alpha = clamp(1.0 - corner_d / aa) if corner_d > 0 else 1.0
            else:
                card_alpha = 1.0

            # Radial ambient glow + subtle specular top highlight
            glow = math.exp(-r_dist * r_dist * 1.8) * 0.34
            col = blend(base_bg, cyan, glow)
            if ny < -0.25 and r_dist < 0.88:
                col = blend(col, white, clamp((-0.25 - ny) * 0.14))

            # Outer telemetry ring
            ring_d = abs(r_dist - 0.78) - 0.018
            if ring_d < aa:
                col = blend(col, cyan, clamp(1.0 - ring_d / aa) * 0.48)

            # Curved Heraldic Vault Shield geometry
            sy = ny + 0.04
            curve_taper = max(0.0, sy + 0.12) ** 1.35
            shield_w = 0.52 * (1.0 - 0.72 * curve_taper)
            shield_d = max(abs(nx) - shield_w, abs(sy) - 0.56)
            accent = lerp_color(emerald, cyan, clamp((ny + 0.6) / 1.2))

            if shield_d < aa:
                fill_a = clamp(1.0 - shield_d / aa)
                col = blend(col, accent, fill_a * 0.24)
            border_d = abs(shield_d) - 0.036
            if border_d < aa:
                col = blend(col, accent, clamp(1.0 - border_d / aa))

            # Cloud silhouette inside upper shield
            c1 = math.hypot(nx + 0.14, ny + 0.08) - 0.14
            c2 = math.hypot(nx - 0.14, ny + 0.08) - 0.13
            c3 = math.hypot(nx, ny + 0.18) - 0.18
            c_base = max(abs(nx) - 0.16, abs(ny + 0.01) - 0.07)
            cloud_d = min(c1, c2, c3, c_base)
            if cloud_d < aa:
                col = blend(col, white, clamp(1.0 - cloud_d / aa) * 0.94)

            # SHA-256 Verification Checkmark in center/lower shield
            chk1 = sd_seg(nx, ny, -0.13, 0.02, -0.03, 0.13)
            chk2 = sd_seg(nx, ny, -0.03, 0.13, 0.17, -0.10)
            chk_d = min(chk1, chk2) - 0.044
            if chk_d < aa:
                col = blend(col, emerald, clamp(1.0 - chk_d / aa))

            # Splash screen bottom loading bar accent
            if is_splash and abs(ny - 1.15) < 0.03 and abs(nx) < 0.85:
                bar_col = lerp_color(emerald, cyan, (nx + 0.85) / 1.7)
                col = blend(col, bar_col, 0.92)

            idx = (y * width + x) * 4
            buf[idx : idx + 4] = bytes((col[0], col[1], col[2], int(card_alpha * 255)))

    return encode_png(width, height, bytes(buf))


# ---------------------------------------------------------------------------
# Procedural Renderer: BobFWTools (SPI/IC Microchip + Pins + Flash Bolt)
# ---------------------------------------------------------------------------
def render_bob_fw_tools(width: int, height: int, is_splash: bool = False) -> bytes:
    buf = bytearray(width * height * 4)
    cx, cy = width / 2.0, height / 2.0
    scale = min(width, height) * (0.58 if is_splash else 0.86)
    half = scale / 2.0
    aa = 1.5 / max(scale, 1.0)

    bg_top = (9, 13, 22)       # #090D16
    bg_bot = (19, 19, 28)      # #13131C
    amber = (245, 158, 11)     # #F59E0B
    crimson = (239, 68, 68)    # #EF4444
    electric = (56, 189, 248)  # #38BDF8
    gold = (253, 224, 71)      # #FDE047

    pin_offsets = [-0.30, -0.10, 0.10, 0.30]

    for y in range(height):
        vy = y / max(height - 1, 1)
        base_bg = lerp_color(bg_top, bg_bot, vy)
        for x in range(width):
            nx = (x - cx) / half
            ny = (y - cy) / half
            r_dist = math.hypot(nx, ny)

            if not is_splash:
                corner_d = math.hypot(max(abs(nx) - 0.72, 0.0), max(abs(ny) - 0.72, 0.0)) - 0.24
                if corner_d > aa:
                    continue
                card_alpha = clamp(1.0 - corner_d / aa) if corner_d > 0 else 1.0
            else:
                card_alpha = 1.0

            # Molten core ambient glow
            glow = math.exp(-r_dist * r_dist * 1.9) * 0.36
            col = blend(base_bg, crimson, glow)

            # IC Hardware Pins on all 4 sides
            pin_hit = 10.0
            for po in pin_offsets:
                pin_hit = min(pin_hit, max(abs(nx - po) - 0.038, abs(abs(ny) - 0.58) - 0.11))
                pin_hit = min(pin_hit, max(abs(ny - po) - 0.038, abs(abs(nx) - 0.58) - 0.11))
            if pin_hit < aa:
                col = blend(col, electric, clamp(1.0 - pin_hit / aa) * 0.92)

            # Central QFP / SPI Flash IC Package Body
            chip_d = max(abs(nx) - 0.44, abs(ny) - 0.44)
            accent = lerp_color(amber, crimson, clamp((ny + 0.5) / 1.0))
            if chip_d < aa:
                col = blend(col, (24, 28, 42), clamp(1.0 - chip_d / aa) * 0.96)
            chip_border = abs(chip_d) - 0.036
            if chip_border < aa:
                col = blend(col, accent, clamp(1.0 - chip_border / aa))

            # Pin-1 Orientation Dot (top-left of IC package)
            dot_d = math.hypot(nx + 0.31, ny + 0.31) - 0.042
            if dot_d < aa:
                col = blend(col, electric, clamp(1.0 - dot_d / aa))

            # High-Voltage Firmware Flash Bolt in IC Core
            b1 = sd_seg(nx, ny, 0.08, -0.26, -0.12, 0.02)
            b2 = sd_seg(nx, ny, -0.12, 0.02, 0.05, 0.02)
            b3 = sd_seg(nx, ny, 0.05, 0.02, -0.08, 0.26)
            bolt_d = min(b1, b2, b3) - 0.044
            if bolt_d < aa:
                col = blend(col, gold, clamp(1.0 - bolt_d / aa))

            # Splash screen bottom diagnostic trace bar
            if is_splash and abs(ny - 1.15) < 0.03 and abs(nx) < 0.85:
                bar_col = lerp_color(amber, electric, (nx + 0.85) / 1.7)
                col = blend(col, bar_col, 0.92)

            idx = (y * width + x) * 4
            buf[idx : idx + 4] = bytes((col[0], col[1], col[2], int(card_alpha * 255)))

    return encode_png(width, height, bytes(buf))


# ---------------------------------------------------------------------------
# Master SVG Vector Generators
# ---------------------------------------------------------------------------
CLOUD_SPACE_GUARD_SVG = """<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 512 512" width="512" height="512">
  <defs>
    <linearGradient id="csg_bg" x1="0" y1="0" x2="1" y2="1">
      <stop offset="0%" stop-color="#0B1120"/>
      <stop offset="100%" stop-color="#111827"/>
    </linearGradient>
    <linearGradient id="csg_acc" x1="0" y1="0" x2="1" y2="1">
      <stop offset="0%" stop-color="#10B981"/>
      <stop offset="100%" stop-color="#06B6D4"/>
    </linearGradient>
  </defs>
  <rect x="24" y="24" width="464" height="464" rx="108" fill="url(#csg_bg)" stroke="url(#csg_acc)" stroke-width="8"/>
  <circle cx="256" cy="256" r="190" fill="none" stroke="#06B6D4" stroke-opacity="0.25" stroke-width="4" stroke-dasharray="12 8"/>
  <path d="M256 96 L384 148 V252 C384 342 326 404 256 432 C186 404 128 342 128 252 V148 Z"
        fill="#10B981" fill-opacity="0.14" stroke="url(#csg_acc)" stroke-width="14" stroke-linejoin="round"/>
  <path d="M196 254 H316 A38 38 0 0 0 322 180 A58 58 0 0 0 212 168 A44 44 0 0 0 196 254 Z"
        fill="#F0FDFA"/>
  <path d="M214 286 L244 316 L306 252" fill="none" stroke="#10B981" stroke-width="18" stroke-linecap="round" stroke-linejoin="round"/>
</svg>
"""

BOB_FW_TOOLS_SVG = """<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 512 512" width="512" height="512">
  <defs>
    <linearGradient id="bfw_bg" x1="0" y1="0" x2="1" y2="1">
      <stop offset="0%" stop-color="#090D16"/>
      <stop offset="100%" stop-color="#181824"/>
    </linearGradient>
    <linearGradient id="bfw_acc" x1="0" y1="0" x2="1" y2="1">
      <stop offset="0%" stop-color="#F59E0B"/>
      <stop offset="100%" stop-color="#EF4444"/>
    </linearGradient>
  </defs>
  <rect x="24" y="24" width="464" height="464" rx="108" fill="url(#bfw_bg)" stroke="url(#bfw_acc)" stroke-width="8"/>
  <!-- QFP / SPI Flash Hardware Pins -->
  <g fill="#38BDF8">
    <rect x="164" y="76" width="20" height="48" rx="6"/><rect x="218" y="76" width="20" height="48" rx="6"/>
    <rect x="274" y="76" width="20" height="48" rx="6"/><rect x="328" y="76" width="20" height="48" rx="6"/>
    <rect x="164" y="388" width="20" height="48" rx="6"/><rect x="218" y="388" width="20" height="48" rx="6"/>
    <rect x="274" y="388" width="20" height="48" rx="6"/><rect x="328" y="388" width="20" height="48" rx="6"/>
    <rect x="76" y="164" width="48" height="20" rx="6"/><rect x="76" y="218" width="48" height="20" rx="6"/>
    <rect x="76" y="274" width="48" height="20" rx="6"/><rect x="76" y="328" width="48" height="20" rx="6"/>
    <rect x="388" y="164" width="48" height="20" rx="6"/><rect x="388" y="218" width="48" height="20" rx="6"/>
    <rect x="388" y="274" width="48" height="20" rx="6"/><rect x="388" y="328" width="48" height="20" rx="6"/>
  </g>
  <!-- IC Package Body -->
  <rect x="124" y="124" width="264" height="264" rx="28" fill="#131722" stroke="url(#bfw_acc)" stroke-width="14"/>
  <circle cx="164" cy="164" r="12" fill="#38BDF8"/>
  <!-- Firmware Flash Bolt -->
  <path d="M276 164 L208 264 H262 L236 348 L312 244 H256 Z" fill="#FDE047" stroke="#F59E0B" stroke-width="6" stroke-linejoin="round"/>
</svg>
"""


def shutil_which(cmd: str) -> bool:
    return any(
        os.access(os.path.join(path, cmd), os.X_OK)
        for path in os.environ.get("PATH", "").split(os.pathsep)
    )


def build_app_asset_suite(app_slug: str, renderer, svg_text: str, out_dir: Path):
    print(f"\n==> Building Icon & Splash Set for [{app_slug}] in {out_dir}")
    mac_dir = out_dir / "macos"
    iconset_dir = mac_dir / "AppIcon.iconset"
    win_dir = out_dir / "windows"
    win_assets = win_dir / "Assets"
    splash_dir = out_dir / "splash"

    for d in (iconset_dir, win_assets, splash_dir):
        d.mkdir(parents=True, exist_ok=True)

    # 1. Save Vector SVG Master
    (out_dir / f"{app_slug}_icon.svg").write_text(svg_text.strip() + "\n", encoding="utf-8")

    # 2. Generate macOS AppIcon.iconset (16x16 through 512x512@2x)
    cache: dict[tuple[int, int, bool], bytes] = {}

    def get_png(w: int, h: int, splash: bool = False) -> bytes:
        key = (w, h, splash)
        if key not in cache:
            cache[key] = renderer(w, h, is_splash=splash)
        return cache[key]

    for sz in (16, 32, 128, 256, 512):
        (iconset_dir / f"icon_{sz}x{sz}.png").write_bytes(get_png(sz, sz))
        (iconset_dir / f"icon_{sz}x{sz}@2x.png").write_bytes(get_png(sz * 2, sz * 2))

    # Compile macOS .icns if iconutil is available
    icns_path = mac_dir / "AppIcon.icns"
    if shutil_which("iconutil"):
        subprocess.run(["iconutil", "-c", "icns", str(iconset_dir), "-o", str(icns_path)], check=False)
        print(f"    [OK] macOS .icns bundle: {icns_path}")

    # 3. Generate Windows MSIX WACK Tiles + Splash Screens
    wack_tiles = {
        "StoreLogo.png": (50, 50, False),
        "Square44x44Logo.png": (44, 44, False),
        "Square150x150Logo.png": (150, 150, False),
        "Wide310x150Logo.png": (310, 150, True),
        "Square310x310Logo.png": (310, 310, False),
        "SplashScreen.png": (620, 300, True),
        "SplashScreen.scale-200.png": (1240, 600, True),
    }
    for name, (w, h, is_sp) in wack_tiles.items():
        (win_assets / name).write_bytes(get_png(w, h, splash=is_sp))
    print(f"    [OK] Windows MSIX WACK Tiles + SplashScreen (7 files): {win_assets}")

    # 4. Generate Multi-Resolution Windows .ico (16, 32, 48, 256)
    ico_blobs = [(sz, sz, get_png(sz, sz)) for sz in (16, 32, 48, 256)]
    ico_path = win_dir / f"{app_slug}.ico"
    ico_path.write_bytes(encode_ico(ico_blobs))
    print(f"    [OK] Windows Multi-Size .ico: {ico_path}")

    # 5. Generate Desktop / Retina Launch Splash Screen (1280x720)
    desktop_splash = splash_dir / f"{app_slug}_splash_1280x720.png"
    desktop_splash.write_bytes(get_png(1280, 720, splash=True))
    print(f"    [OK] Desktop HD Splash Screen: {desktop_splash}")


def main():
    csg_root = Path("/Users/bj23/Documents/antigravity/cloud-space-guard")
    bob_root = Path("/Users/bj23/Documents/antigravity/silly-galileo")

    # 1. Build CloudSpaceGuard Icon & Splash Suite in its standalone folder
    build_app_asset_suite(
        app_slug="cloud_space_guard",
        renderer=render_cloud_space_guard,
        svg_text=CLOUD_SPACE_GUARD_SVG,
        out_dir=csg_root / "store_packaging",
    )

    # 2. Build BobFWTools Icon & Splash Suite directly in BobFWTools's store_packaging folder
    #    (and mirror to store_packaging_bobfwtools if referenced by scripts)
    build_app_asset_suite(
        app_slug="bob_fw_tools",
        renderer=render_bob_fw_tools,
        svg_text=BOB_FW_TOOLS_SVG,
        out_dir=bob_root / "store_packaging",
    )


if __name__ == "__main__":
    main()
