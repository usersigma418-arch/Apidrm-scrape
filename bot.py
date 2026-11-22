import asyncio
import html
import os
import re
import shutil
import subprocess
import tempfile
import threading
import zipfile
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path
from telethon import TelegramClient, events

API_ID_RAW = os.environ.get("API_ID", "").strip()
API_HASH = os.environ.get("API_HASH", "").strip()
BOT_TOKEN = os.environ.get("BOT_TOKEN", "").strip()

if not API_ID_RAW or not API_HASH or not BOT_TOKEN:
    raise RuntimeError("API_ID, API_HASH, aur BOT_TOKEN teeno env variables set hone chahiye!")

API_ID = int(API_ID_RAW)

MAX_APK_BYTES = 45 * 1024 * 1024
MAX_SEND_BYTES = 49 * 1024 * 1024

SCAN_EXTENSIONS = {
    ".java", ".kt", ".kts", ".xml", ".json", ".properties",
    ".yml", ".yaml", ".txt", ".js", ".ts", ".jsx", ".tsx",
    ".html", ".gradle", ".cfg", ".conf", ".env", ".smil", ".mpd"
}

URL_PATTERN = re.compile(r"https?://[A-Za-z0-9\-._~:/?#\[\]@!$&'()*+,;=%]+")

API_PATH_PATTERN = re.compile(
    r"""(?:["'`])(/(?:api|v[1-9]|graphql|auth|token|license|drm|stream|manifest|player|config)[A-Za-z0-9_\-./?=&%]*)(?:["'`])""",
    re.IGNORECASE,
)

AES_PATTERNS = {
    "AES / Cipher / KeySpec Usage": re.compile(
        r"""(?i)(?:AES(?:/(?:CBC|GCM|CTR|ECB))?(?:/(?:PKCS5Padding|PKCS7Padding|NoPadding))?|SecretKeySpec|IvParameterSpec|GCMParameterSpec|Cipher\.getInstance)"""
    ),
    "AES / Secret / IV Assignment": re.compile(
        r"""(?i)(?:aes[_-]?key|aes[_-]?iv|encryption[_-]?key|decryption[_-]?key|secret[_-]?key|init[_-]?vector|iv[_-]?key)\s*[:=]\s*["']?([A-Za-z0-9_\-+/=]{8,160})["']?"""
    ),
    "Hex Key/IV Candidate (32/64 hex)": re.compile(
        r"""(?i)(?:aes|key|iv|secret|cipher|salt|kid)[A-Za-z0-9_ -]{0,25}[:=]\s*["']?([0-9a-fA-F]{32}|[0-9a-fA-F]{64})["']?"""
    ),
    "Base64 Key/Secret Candidate": re.compile(
        r"""(?i)(?:aes|key|iv|secret|cipher|token|auth)[A-Za-z0-9_ -]{0,25}[:=]\s*["']([A-Za-z0-9+/]{16,120}={0,2})["']"""
    ),
    "PEM Private/Public Key Block": re.compile(
        r"-----BEGIN [A-Z0-9 ]+ KEY-----"
    ),
}

DRM_PATTERNS = {
    "DRM / License / Stream URL": re.compile(
        r"""https?://[^\s"'<>)]+(?:widevine|playready|fairplay|clearkey|license|drm|\.mpd|\.m3u8|keyserver)[^\s"'<>)]*""",
        re.IGNORECASE,
    ),
    "ClearKey / KID / Key Assign": re.compile(
        r"""(?i)(?:clearkey|drm_key|license_key|widevine_url|license_url|kid|key_id)\s*[:=]\s*["']?([A-Za-z0-9_\-+/=:.]{8,120})["']?"""
    ),
}

API_KEY_PATTERNS = {
    "Google / Firebase Key": re.compile(r"AIza[0-9A-Za-z\-_]{35}"),
    "AWS Access Key": re.compile(r"AKIA[0-9A-Z]{16}"),
    "GitHub Token": re.compile(r"(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{36,}"),
    "Stripe / Secret Key": re.compile(r"(?:sk|rk)_(?:live|test)_[0-9A-Za-z]{16,}"),
    "JWT Token": re.compile(r"eyJ[A-Za-z0-9\-_]+\.eyJ[A-Za-z0-9\-_]+\.[A-Za-z0-9\-_]+"),
    "API Key / Secret Assignment": re.compile(
        r"""(?i)(?:api[_-]?key|api[_-]?secret|client[_-]?secret|app[_-]?secret|auth[_-]?token|bearer|x-api-key)\s*[:=]\s*["']([A-Za-z0-9_\-\.\/+=]{10,140})["']"""
    ),
}

NOISY_DOMAINS = (
    "schemas.android.com",
    "www.w3.org",
    "ns.adobe.com",
    "purl.org",
    "xmlpull.org",
    "developer.android.com",
)

client = TelegramClient("/tmp/apk_bot_session", API_ID, API_HASH)


def start_health_server():
    port = int(os.environ.get("PORT", "10000"))

    class Handler(BaseHTTPRequestHandler):
        def do_GET(self):
            self.send_response(200)
            self.send_header("Content-Type", "text/plain")
            self.end_headers()
            self.wfile.write(b"OK")

        def log_message(self, format, *args):
            return

    server = HTTPServer(("0.0.0.0", port), Handler)
    threading.Thread(target=server.serve_forever, daemon=True).start()


def is_noisy_url(url: str) -> bool:
    clean = url.rstrip(".,);]}>\"'")
    return any(d in clean for d in NOISY_DOMAINS)


def scan_decompiled(out_dir: Path):
    urls = set()
    api_paths = set()
    aes_hits = {k: set() for k in AES_PATTERNS}
    drm_hits = {k: set() for k in DRM_PATTERNS}
    key_hits = {k: set() for k in API_KEY_PATTERNS}
    scanned_count = 0

    for root, _, files in os.walk(out_dir):
        for fname in files:
            fpath = Path(root) / fname
            if fpath.suffix.lower() not in SCAN_EXTENSIONS:
                continue
            try:
                if fpath.stat().st_size > 1.5 * 1024 * 1024:
                    continue
                text = fpath.read_text(encoding="utf-8", errors="ignore")
            except Exception:
                continue

            scanned_count += 1

            for u in URL_PATTERN.findall(text):
                clean_u = u.rstrip(".,);]}>\"'")
                if not is_noisy_url(clean_u):
                    urls.add(clean_u)

            for p in API_PATH_PATTERN.findall(text):
                api_paths.add(p)

            for label, pat in AES_PATTERNS.items():
                for match in pat.findall(text):
                    val = match if isinstance(match, str) else match[0]
                    aes_hits[label].add(val.strip())

            for label, pat in DRM_PATTERNS.items():
                for match in pat.findall(text):
                    val = match if isinstance(match, str) else match[0]
                    drm_hits[label].add(val.strip())

            for label, pat in API_KEY_PATTERNS.items():
                for match in pat.findall(text):
                    val = match if isinstance(match, str) else match[0]
                    key_hits[label].add(val.strip())

    api_or_media_urls = sorted(
        [
            u for u in urls
            if any(k in u.lower() for k in ("api", "v1", "v2", "v3", "graphql", "drm", "license", "widevine", "clearkey", "mpd", "m3u8", "stream", "auth"))
        ]
    )

    return scanned_count, api_or_media_urls, sorted(api_paths), aes_hits, drm_hits, key_hits


def write_full_report(report_path: Path, filename: str, scanned_count: int, api_urls, api_paths, aes_hits, drm_hits, key_hits):
    lines = [
        f"APK Scan Report: {filename}",
        f"Scanned text/code files: {scanned_count}",
        "=" * 60,
        "",
        "[AES & CRYPTO INDICATORS]",
    ]
    for label, vals in aes_hits.items():
        lines.append(f"- {label} ({len(vals)}):")
        for v in sorted(vals):
            lines.append(f"    {v}")

    lines += ["", "[DRM / LICENSE / STREAM INDICATORS]"]
    for label, vals in drm_hits.items():
        lines.append(f"- {label} ({len(vals)}):")
        for v in sorted(vals):
            lines.append(f"    {v}")

    lines += ["", "[API KEYS / TOKENS]"]
    for label, vals in key_hits.items():
        lines.append(f"- {label} ({len(vals)}):")
        for v in sorted(vals):
            lines.append(f"    {v}")

    lines += ["", f"[API / STREAM URLs ({len(api_urls)})]"]
    for u in api_urls:
        lines.append(f"    {u}")

    lines += ["", f"[API ROUTES / PATHS ({len(api_paths)})]"]
    for p in api_paths:
        lines.append(f"    {p}")

    report_path.write_text("\n".join(lines), encoding="utf-8")


def make_zip(source_dir: Path, zip_path: Path):
    with zipfile.ZipFile(zip_path, "w", zipfile.ZIP_DEFLATED, compresslevel=6) as zf:
        for root, _, files in os.walk(source_dir):
            for fname in files:
                full = Path(root) / fname
                rel = full.relative_to(source_dir)
                zf.write(full, arcname=str(rel))


def run_jadx_and_scan(apk_path: Path, display_name: str):
    work_dir = apk_path.parent
    decompiled_dir = work_dir / "decompiled"

    cmd = [
        "jadx",
        "-d", str(decompiled_dir),
        "--threads-count", "2",
        "--no-imports",
        "--no-res",
        str(apk_path),
    ]

    proc = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
    if not decompiled_dir.exists():
        err = (proc.stderr or proc.stdout or "jadx failed")[-700:]
        raise RuntimeError(f"jadx decompile fail:\n{err}")

    scanned_count, api_urls, api_paths, aes_hits, drm_hits, key_hits = scan_decompiled(decompiled_dir)

    report_path = work_dir / f"{Path(display_name).stem}_report.txt"
    write_full_report(report_path, display_name, scanned_count, api_urls, api_paths, aes_hits, drm_hits, key_hits)

    zip_path = work_dir / f"{Path(display_name).stem}_decompiled.zip"
    make_zip(decompiled_dir, zip_path)

    return scanned_count, api_urls, api_paths, aes_hits, drm_hits, key_hits, report_path, zip_path


@client.on(events.NewMessage(pattern=r"^/(start|help)$"))
async def start_handler(event):
    await event.reply(
        "<b>APK AES, DRM &amp; API Inspector Bot (MTProto)</b>\n\n"
        "• <b>~45 MB tak</b> ki <code>.apk</code> file directly upload kar sakte ho.\n"
        "• Main AES/crypto patterns, DRM/license indicators, API endpoints/keys, <code>report.txt</code> aur ZIP bhejunga.",
        parse_mode="html",
    )


@client.on(events.NewMessage)
async def apk_handler(event):
    if not event.file or not event.file.name:
        return

    filename = event.file.name
    if not filename.lower().endswith(".apk"):
        return

    file_size = event.file.size or 0
    if file_size > MAX_APK_BYTES:
        size_mb = round(file_size / (1024 * 1024), 2)
        await event.reply(
            f"⚠️ File <b>{size_mb} MB</b> ki hai. Current limit <b>45 MB</b> set ki gayi hai.",
            parse_mode="html",
        )
        return

    status = await event.reply(
        f"📥 <code>{html.escape(filename)}</code> ({round(file_size / (1024 * 1024), 1)} MB) download kar raha hoon...",
        parse_mode="html",
    )

    work_dir = Path(tempfile.mkdtemp(prefix="apk_mt_"))
    apk_path = work_dir / "input.apk"

    try:
        await event.download_media(file=str(apk_path))

        await status.edit(
            "⚙️ <code>jadx</code> se decompile aur AES/DRM/API scan chal raha hai...",
            parse_mode="html",
        )

        loop = asyncio.get_running_loop()
        scanned_count, api_urls, api_paths, aes_hits, drm_hits, key_hits, report_path, zip_path = (
            await loop.run_in_executor(None, run_jadx_and_scan, apk_path, filename)
        )

        def format_section(hits_dict, max_per_cat=3, max_len=50):
            out = []
            for label, vals in hits_dict.items():
                if vals:
                    sample = ", ".join(f"<code>{html.escape(v[:max_len])}</code>" for v in sorted(vals)[:max_per_cat])
                    out.append(f"• <b>{html.escape(label)}</b> ({len(vals)}): {sample}")
            return "\n".join(out) if out else "• Koi match nahi mila"

        aes_block = format_section(aes_hits)
        drm_block = format_section(drm_hits)
        key_block = format_section(key_hits)
        url_lines = [f"• <code>{html.escape(u[:90])}</code>" for u in api_urls[:8]]
        path_lines = [f"• <code>{html.escape(p[:65])}</code>" for p in api_paths[:8]]

        summary = (
            f"✅ <b>Scan Complete:</b> <code>{html.escape(filename)}</code>\n"
            f"📄 Scanned files: <b>{scanned_count}</b>\n\n"
            f"<b>🛡️ AES &amp; Crypto:</b>\n{aes_block}\n\n"
            f"<b>🔐 DRM / License:</b>\n{drm_block}\n\n"
            f"<b>🔑 API Keys / Tokens:</b>\n{key_block}\n\n"
            f"<b>🌐 API / Stream URLs ({len(api_urls)}):</b>\n"
            + ("\n".join(url_lines) if url_lines else "• Koi API/stream URL nahi mila")
            + f"\n\n<b>🛤️ API Paths ({len(api_paths)}):</b>\n"
            + ("\n".join(path_lines) if path_lines else "• Koi relative API path nahi mila")
        )

        if len(summary) > 3950:
            summary = summary[:3910] + "\n... (full details report.txt mein hain)"

        await status.edit(summary, parse_mode="html", link_preview=False)

        if report_path.exists() and report_path.stat().st_size <= MAX_SEND_BYTES:
            await client.send_file(
                event.chat_id,
                str(report_path),
                caption=f"📝 Full report: <code>{html.escape(report_path.name)}</code>",
                parse_mode="html",
            )

        if zip_path.exists() and zip_path.stat().st_size <= MAX_SEND_BYTES:
            await client.send_file(
                event.chat_id,
                str(zip_path),
                caption=f"📦 Decompiled ZIP: <code>{html.escape(zip_path.name)}</code>",
                parse_mode="html",
            )
        else:
            size_mb = round(zip_path.stat().st_size / (1024 * 1024), 2) if zip_path.exists() else 0
            await event.reply(
                f"ℹ️ ZIP size <b>{size_mb} MB</b> hai, par saari findings <code>report.txt</code> mein aa gayi hain.",
                parse_mode="html",
            )

    except subprocess.TimeoutExpired:
        await status.edit("⏱️ Decompilation timeout ho gaya.", parse_mode="html")
    except Exception as e:
        await status.edit(f"❌ Error: <code>{html.escape(str(e)[:600])}</code>", parse_mode="html")
    finally:
        shutil.rmtree(work_dir, ignore_errors=True)


async def main():
    start_health_server()
    await client.start(bot_token=BOT_TOKEN)
    print("MTProto APK AES/DRM/API Bot running...")
    await client.run_until_disconnected()


if __name__ == "__main__":
    asyncio.run(main())
