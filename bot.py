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
import telebot

BOT_TOKEN = os.environ.get("BOT_TOKEN", "").strip()
if not BOT_TOKEN:
    raise RuntimeError("BOT_TOKEN environment variable set nahi hai!")

bot = telebot.TeleBot(BOT_TOKEN, parse_mode="HTML")
MAX_UPLOAD_BYTES = 49 * 1024 * 1024

SCAN_EXTENSIONS = {
    ".java", ".kt", ".kts", ".xml", ".json", ".properties",
    ".yml", ".yaml", ".txt", ".js", ".ts", ".jsx", ".tsx",
    ".html", ".gradle", ".cfg", ".conf", ".env", ".smil", ".mpd"
}

URL_PATTERN = re.compile(r"https?://[A-Za-z0-9\-._~:/?#\[\]@!$&'()*+,;=%]+")

# API endpoints, REST paths, GraphQL, manifest/stream URLs
API_PATH_PATTERN = re.compile(
    r"""(?:["'`])(/(?:api|v[1-9]|graphql|auth|token|license|drm|stream|manifest|player|config)[A-Za-z0-9_\-./?=&%]*)(?:["'`])""",
    re.IGNORECASE,
)

# DRM & License specific indicators
DRM_PATTERNS = {
    "DRM / License / Stream URL": re.compile(
        r"""https?://[^\s"'<>)]+(?:widevine|playready|fairplay|clearkey|license|drm|\.mpd|\.m3u8|keyserver)[^\s"'<>)]*""",
        re.IGNORECASE,
    ),
    "ClearKey / KID / Key Assign": re.compile(
        r"""(?i)(?:clearkey|drm_key|license_key|widevine_url|license_url|kid|key_id)\s*[:=]\s*["']?([A-Za-z0-9_\-+/=:.]{8,120})["']?"""
    ),
    "32-char Hex Key (128-bit AES/KID)": re.compile(
        r"""(?i)(?:key|kid|drm|secret|iv|token)[A-Za-z0-9_]*\s*[:=]\s*["']?([0-9a-f]{32})["']?"""
    ),
}

# API Keys, Tokens, Cloud keys
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


def start_health_server():
    """Render Web Service port requirement ke liye tiny HTTP server."""
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
    drm_hits = {k: set() for k in DRM_PATTERNS}
    key_hits = {k: set() for k in API_KEY_PATTERNS}
    scanned_count = 0

    for root, _, files in os.walk(out_dir):
        for fname in files:
            fpath = Path(root) / fname
            if fpath.suffix.lower() not in SCAN_EXTENSIONS:
                continue
            try:
                if fpath.stat().st_size > 2 * 1024 * 1024:
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

            for label, pat in DRM_PATTERNS.items():
                for match in pat.findall(text):
                    val = match if isinstance(match, str) else match[0]
                    drm_hits[label].add(val.strip())

            for label, pat in API_KEY_PATTERNS.items():
                for match in pat.findall(text):
                    val = match if isinstance(match, str) else match[0]
                    key_hits[label].add(val.strip())

    # URLs mein se API/stream wale URLs ko alag se prioritize karo
    api_or_media_urls = sorted(
        [
            u for u in urls
            if any(k in u.lower() for k in ("api", "v1", "v2", "v3", "graphql", "drm", "license", "widevine", "clearkey", "mpd", "m3u8", "stream", "auth"))
        ]
    )

    return scanned_count, api_or_media_urls, sorted(api_paths), drm_hits, key_hits


def make_zip(source_dir: Path, zip_path: Path):
    with zipfile.ZipFile(zip_path, "w", zipfile.ZIP_DEFLATED, compresslevel=6) as zf:
        for root, _, files in os.walk(source_dir):
            for fname in files:
                full = Path(root) / fname
                rel = full.relative_to(source_dir)
                zf.write(full, arcname=str(rel))


@bot.message_handler(commands=["start", "help"])
def welcome(message):
    bot.reply_to(
        message,
        "<b>APK API &amp; DRM Inspector Bot</b>\n\n"
        "Koi <b>.apk</b> file bhejo (open-source / apne APKs ke liye).\n"
        "Main decompile karke nikaalunga:\n"
        "• <b>DRM / License / Stream URLs &amp; Key patterns</b>\n"
        "• <b>API Endpoints &amp; Paths</b>\n"
        "• <b>API Keys / Tokens</b>\n"
        "• <b>Decompiled Source ZIP</b> (~50 MB tak)"
    )


@bot.message_handler(content_types=["document"])
def handle_apk(message):
    doc = message.document
    filename = doc.file_name or "app.apk"

    if not filename.lower().endswith(".apk"):
        bot.reply_to(message, "Bhai sirf <b>.apk</b> file bhejo.")
        return

    status = bot.reply_to(message, f"📥 <code>{html.escape(filename)}</code> download kar raha hoon...")
    work_dir = Path(tempfile.mkdtemp(prefix="apk_scan_"))

    try:
        file_info = bot.get_file(doc.file_id)
        apk_bytes = bot.download_file(file_info.file_path)
        apk_path = work_dir / "target.apk"
        apk_path.write_bytes(apk_bytes)

        bot.edit_message_text(
            "⚙️ <code>jadx</code> se decompile kar raha hoon...",
            chat_id=message.chat.id,
            message_id=status.message_id,
        )

        decompiled_dir = work_dir / "decompiled"
        cmd = [
            "jadx",
            "-d", str(decompiled_dir),
            "--threads-count", "2",
            "--no-imports",
            str(apk_path),
        ]

        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=240)

        if not decompiled_dir.exists():
            err = html.escape((proc.stderr or proc.stdout or "jadx failed")[-700:])
            bot.edit_message_text(
                f"❌ Decompile fail:\n<pre>{err}</pre>",
                chat_id=message.chat.id,
                message_id=status.message_id,
            )
            return

        bot.edit_message_text(
            "🔐 DRM indicators, APIs aur keys scan kar raha hoon...",
            chat_id=message.chat.id,
            message_id=status.message_id,
        )

        scanned_count, api_urls, api_paths, drm_hits, key_hits = scan_decompiled(decompiled_dir)

        drm_lines = []
        for label, vals in drm_hits.items():
            if vals:
                sample = ", ".join(f"<code>{html.escape(v[:55])}</code>" for v in sorted(vals)[:4])
                drm_lines.append(f"• <b>{html.escape(label)}</b> ({len(vals)}): {sample}")

        key_lines = []
        for label, vals in key_hits.items():
            if vals:
                sample = ", ".join(f"<code>{html.escape(v[:45])}</code>" for v in sorted(vals)[:4])
                key_lines.append(f"• <b>{html.escape(label)}</b> ({len(vals)}): {sample}")

        url_lines = [f"• <code>{html.escape(u[:95])}</code>" for u in api_urls[:10]]
        path_lines = [f"• <code>{html.escape(p[:70])}</code>" for p in api_paths[:10]]

        report = (
            f"✅ <b>Report:</b> <code>{html.escape(filename)}</code>\n"
            f"📄 Scanned files: <b>{scanned_count}</b>\n\n"
            f"<b>🔐 DRM / License / Key Patterns:</b>\n"
            + ("\n".join(drm_lines) if drm_lines else "• Koi direct DRM key/URL pattern nahi mila")
            + "\n\n<b>🔑 API Keys / Tokens:</b>\n"
            + ("\n".join(key_lines) if key_lines else "• Koi obvious hardcoded key nahi mila")
            + f"\n\n<b>🌐 API / Stream URLs ({len(api_urls)}):</b>\n"
            + ("\n".join(url_lines) if url_lines else "• Koi API/stream URL nahi mila")
            + f"\n\n<b>🛤️ API Routes/Paths ({len(api_paths)}):</b>\n"
            + ("\n".join(path_lines) if path_lines else "• Koi relative API path nahi mila")
        )

        if len(report) > 3950:
            report = report[:3920] + "\n... (truncated)"

        bot.edit_message_text(
            report,
            chat_id=message.chat.id,
            message_id=status.message_id,
            disable_web_page_preview=True,
        )

        zip_path = work_dir / f"{Path(filename).stem}_decompiled.zip"
        make_zip(decompiled_dir, zip_path)

        if zip_path.exists() and zip_path.stat().st_size <= MAX_UPLOAD_BYTES:
            with open(zip_path, "rb") as f:
                bot.send_document(
                    message.chat.id,
                    f,
                    caption=f"📦 Decompiled files: <code>{html.escape(zip_path.name)}</code>",
                )
        else:
            size_mb = round(zip_path.stat().st_size / (1024 * 1024), 2) if zip_path.exists() else 0
            bot.send_message(
                message.chat.id,
                f"⚠️ ZIP size <b>{size_mb} MB</b> hai, standard Bot API (~50 MB) limit se zyada.",
            )

    except subprocess.TimeoutExpired:
        bot.edit_message_text(
            "⏱️ Time limit exceed ho gayi (APK heavy hai).",
            chat_id=message.chat.id,
            message_id=status.message_id,
        )
    except Exception as e:
        bot.edit_message_text(
            f"❌ Error: <code>{html.escape(str(e)[:500])}</code>",
            chat_id=message.chat.id,
            message_id=status.message_id,
        )
    finally:
        shutil.rmtree(work_dir, ignore_errors=True)


if __name__ == "__main__":
    start_health_server()
    print("APK API & DRM Inspector Bot running...")
    bot.infinity_polling(skip_pending=True)
      
