import asyncio
import glob
import httpx
import logging
import os
import re
import tempfile
import time

from dotenv import load_dotenv
load_dotenv()

from telegram import Update, InlineKeyboardButton, InlineKeyboardMarkup
from telegram.ext import (
    Application,
    CommandHandler,
    MessageHandler,
    CallbackQueryHandler,
    ContextTypes,
    filters,
)

import anna_archive
import prowlarr
import downloader
import virustotal
logging.basicConfig(
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    level=logging.INFO,
)
logger = logging.getLogger(__name__)

TELEGRAM_TOKEN = os.environ["TELEGRAM_TOKEN"]
ALLOWED_USER_IDS: set[int] = set()
for _uid in os.environ.get("ALLOWED_USER_IDS", "").split(","):
    _uid = _uid.strip()
    if _uid:
        try:
            ALLOWED_USER_IDS.add(int(_uid))
        except ValueError:
            logger.warning(f"ALLOWED_USER_IDS: ignoring non-numeric value {_uid!r}")
LOCAL_API_SERVER = os.environ.get("LOCAL_API_SERVER", "").rstrip("/")
GITHUB_REPO = os.environ.get("GITHUB_REPO", "candychoc0/annas-bot")
_VALID_FORMATS = {"epub", "pdf"}
ALLOWED_FORMATS: list[str] = [
    f for f in (s.strip() for s in os.environ.get("ALLOWED_FORMATS", "epub,pdf").split(","))
    if f in _VALID_FORMATS
] or ["epub"]
VERSION = "1.1.1"
MAX_RESULTS = 10
MAX_FILE_SIZE = 400 * 1024 * 1024 if LOCAL_API_SERVER else 50 * 1024 * 1024
MAX_QUERY_LENGTH = 200
RATE_LIMIT_SECONDS = 5
_notified_update: str | None = None

# ── Translations ───────────────────────────────────────────────────────────────

STRINGS = {
    "fr": {
        "start": "Bonjour ! Envoie-moi le titre du livre que tu veux télécharger.\nTu pourras ensuite choisir le résultat à télécharger.",
        "rate_limit": "Attends {n} secondes entre deux recherches.",
        "query_too_long": "Requête trop longue (max {n} caractères).",
        "searching": "Recherche en cours...",
        "no_results": "Aucun résultat trouvé pour « {q} ».\nEssaie un autre titre ou orthographe.",
        "results": "{n} résultat{s} trouvé{s} :",
        "choose_format": "« {title} »\nQuel format veux-tu ?",
        "cancel": "Annuler",
        "preparing": "Recherche du fichier",
        "sending": "Envoi de « {title} »...",
        "done": "C'est fait ! Bonne lecture :D",
        "mirrors_fail": "Les sources de téléchargement sont indisponibles pour l'instant.\nRéessaie dans quelques minutes ou essaie un autre titre.",
        "size_limit": "Aucun résultat disponible dans la limite de taille.\nEssaie un autre titre.",
        "expired": "Résultat expiré, refais une recherche.",
        "torrent_wait": "Envoi vers le client torrent pour « {title} »...\nSurveillance du dossier de téléchargement...",
        "still_waiting": "Toujours en attente pour « {title} »...\nMerci de patienter.",
        "dl_cancelled": "Téléchargement annulé.",
        "no_dl": "Aucun téléchargement en cours.",
        "search_cancelled": "Recherche annulée. Essaie un autre titre !",
        "retry": "Essai du résultat suivant : « {title} »...",
        "choose_result": "Choisis un résultat :",
    },
    "en": {
        "start": "Hello! Send me the title of the book you want to download.\nYou can then choose the result to download.",
        "rate_limit": "Please wait {n} seconds between searches.",
        "query_too_long": "Query too long (max {n} characters).",
        "searching": "Searching...",
        "no_results": "No results found for « {q} ».\nTry a different title or spelling.",
        "results": "{n} result{s} found:",
        "choose_format": "« {title} »\nWhich format do you want?",
        "cancel": "Cancel",
        "preparing": "Looking for file",
        "sending": "Sending « {title} »...",
        "done": "Done! Enjoy your book :D",
        "mirrors_fail": "Download sources are unavailable right now.\nTry again in a few minutes or try another title.",
        "size_limit": "No results available within the size limit.\nTry another title.",
        "expired": "Result expired, please search again.",
        "torrent_wait": "Sending to torrent client for « {title} »...\nWatching download folder...",
        "still_waiting": "Still waiting for « {title} »...\nPlease be patient.",
        "dl_cancelled": "Download cancelled.",
        "no_dl": "No active download.",
        "search_cancelled": "Search cancelled. Try another title!",
        "retry": "Trying next result: « {title} »...",
        "choose_result": "Choose a result:",
    },
}

def _t(context: ContextTypes.DEFAULT_TYPE, key: str, **kwargs) -> str:
    lang = context.user_data.get("lang", "fr")
    text = STRINGS.get(lang, STRINGS["fr"]).get(key, key)
    return text.format(**kwargs) if kwargs else text

def _cancel_kb(context: ContextTypes.DEFAULT_TYPE) -> InlineKeyboardMarkup:
    return InlineKeyboardMarkup([[InlineKeyboardButton(_t(context, "cancel"), callback_data="cancel_dl")]])

# ── Helpers ────────────────────────────────────────────────────────────────────

def _fmt_size(size_bytes: int) -> str:
    if not size_bytes:
        return "?"
    if size_bytes < 1024 * 1024:
        return f"{size_bytes / 1024:.0f} Ko"
    return f"{size_bytes / 1024 / 1024:.1f} Mo"


def _cleanup_orphaned_temp_files() -> None:
    pattern = os.path.join(tempfile.gettempdir(), "annas_*")
    count = 0
    for path in glob.glob(pattern):
        try:
            os.remove(path)
            count += 1
        except Exception:
            pass
    if count:
        logger.info(f"Cleaned up {count} orphaned temp file(s)")


def _is_allowed(update: Update) -> bool:
    uid = update.effective_user.id if update.effective_user else None
    return uid in ALLOWED_USER_IDS


def _is_newer_version(remote: str, local: str) -> bool:
    def parse(v: str) -> tuple:
        try:
            return tuple(int(x) for x in v.lstrip("v").split("."))
        except ValueError:
            return (0,)
    return parse(remote) > parse(local)


async def check_for_updates(context: ContextTypes.DEFAULT_TYPE) -> None:
    global _notified_update
    if not GITHUB_REPO:
        return
    try:
        async with httpx.AsyncClient(timeout=10, headers={"User-Agent": "annas-bot"}) as client:
            resp = await client.get(
                f"https://api.github.com/repos/{GITHUB_REPO}/releases/latest",
                headers={"Accept": "application/vnd.github+json"},
            )
            if resp.status_code == 404:
                return
            resp.raise_for_status()
            data = resp.json()
    except Exception as e:
        logger.warning(f"Update check failed: {e}")
        return

    tag = data.get("tag_name", "")
    if not tag or tag == _notified_update or not _is_newer_version(tag, VERSION):
        return

    _notified_update = tag
    url = data.get("html_url", f"https://github.com/{GITHUB_REPO}/releases/latest")
    msg = (
        f"Nouvelle version disponible : *{tag}*\n"
        f"Version installée : `{VERSION}`\n"
        f"[Voir les changements]({url})"
    )
    for uid in ALLOWED_USER_IDS:
        try:
            await context.bot.send_message(uid, msg, parse_mode="Markdown", disable_web_page_preview=True)
        except Exception as e:
            logger.warning(f"Could not notify user {uid} about update: {e}")


# ── Handlers ───────────────────────────────────────────────────────────────────

async def start(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    if not _is_allowed(update):
        return
    keyboard = InlineKeyboardMarkup([
        [
            InlineKeyboardButton("🇫🇷 Français", callback_data="lang_fr"),
            InlineKeyboardButton("🇬🇧 English", callback_data="lang_en"),
        ]
    ])
    await update.message.reply_text(
        "🇫🇷 Choisis ta langue\n🇬🇧 Choose your language",
        reply_markup=keyboard,
    )


async def handle_language(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    query = update.callback_query
    await query.answer()
    if not _is_allowed(update):
        return
    lang = query.data.split("_")[1]
    context.user_data["lang"] = lang
    await query.edit_message_text(_t(context, "start"))


async def handle_search(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    if not _is_allowed(update):
        return

    # If no language set yet, prompt for it
    if "lang" not in context.user_data:
        keyboard = InlineKeyboardMarkup([
            [
                InlineKeyboardButton("Français", callback_data="lang_fr"),
                InlineKeyboardButton("English", callback_data="lang_en"),
            ]
        ])
        await update.message.reply_text(
            "Choisis ta langue\nChoose your language",
            reply_markup=keyboard,
        )
        return

    now = time.monotonic()
    last = context.user_data.get("last_search_at", 0.0)
    if now - last < RATE_LIMIT_SECONDS:
        await update.message.reply_text(_t(context, "rate_limit", n=RATE_LIMIT_SECONDS))
        return
    context.user_data["last_search_at"] = now

    q = update.message.text.strip()
    if not q:
        return

    if len(q) > MAX_QUERY_LENGTH:
        await update.message.reply_text(_t(context, "query_too_long", n=MAX_QUERY_LENGTH))
        return

    msg = await update.message.reply_text(_t(context, "searching"))

    aa_results, pr_results = await asyncio.gather(
        _safe_search(anna_archive.search, q, "Anna's Archive"),
        _safe_search(prowlarr.search, q, "Prowlarr"),
    )

    logger.info(f"=== Results for '{q}' ===")
    for r in aa_results:
        logger.info(f"  [AA] {r.get('title')!r} — {r.get('ext')} — {_fmt_size(r.get('size_bytes',0))}")
    for r in pr_results:
        logger.info(f"  [PR] {r.get('title')!r} — {r.get('ext')} — torrent={r.get('is_torrent')}")

    def _sort_key(r):
        return (0 if r.get("ext") == "epub" else 1, 0 if not r.get("is_torrent") else 1)

    direct = [r for r in aa_results + pr_results if not r.get("is_torrent")]
    torrents = [r for r in pr_results if r.get("is_torrent")]
    all_results = sorted(direct, key=_sort_key) + torrents
    filtered = [r for r in all_results if not (r.get("size_bytes", 0) > MAX_FILE_SIZE)]

    seen_titles: set[str] = set()
    results = []
    for r in filtered:
        norm = re.sub(r"[^\w]", "", (r.get("title") or "")).lower()[:35]
        if norm and norm in seen_titles:
            continue
        if norm:
            seen_titles.add(norm)
        results.append(r)
        if len(results) >= MAX_RESULTS:
            break

    has_epub = any(r.get("ext") == "epub" for r in results)

    if not results:
        await msg.edit_text(_t(context, "no_results", q=q))
        return

    context.user_data["results"] = results

    buttons = []
    for i, r in enumerate(results):
        if r.get("ext") != "epub" and has_epub:
            continue
        title = r.get("title") or "?"
        author = r.get("author") or ""
        title_short = title[:45] + "…" if len(title) > 45 else title
        label = f"{title_short}"
        if author:
            label += f" – {author[:20]}"
        buttons.append([InlineKeyboardButton(label, callback_data=f"dl_{i}")])

    n = len(buttons)
    s = "s" if n > 1 else ""
    await msg.edit_text(
        _t(context, "results", n=n, s=s),
        reply_markup=InlineKeyboardMarkup(buttons),
    )


async def _safe_search(fn, query: str, source_name: str) -> list[dict]:
    try:
        return await fn(query)
    except Exception as e:
        logger.warning(f"{source_name} search error: {e}")
        return []


async def _animate_preparing(query, context, started: asyncio.Event, reply_markup=None) -> None:
    base = _t(context, "preparing")
    frames = [f"{base} .", f"{base} ..", f"{base} ..."]
    i = 0
    try:
        while not started.is_set():
            try:
                await query.edit_message_text(frames[i % len(frames)], reply_markup=reply_markup)
            except Exception:
                pass
            i += 1
            await asyncio.sleep(1)
    except asyncio.CancelledError:
        pass


async def handle_download(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    query = update.callback_query
    await query.answer()

    if not _is_allowed(update):
        return

    data = query.data or ""
    if not data.startswith("dl_"):
        return

    try:
        idx = int(data[3:])
    except ValueError:
        return

    results = context.user_data.get("results", [])
    if idx >= len(results):
        await query.edit_message_text(_t(context, "expired"))
        return

    result = results[idx]
    if result.get("ext") == "epub" and len(ALLOWED_FORMATS) > 1:
        title = result.get("title") or "ce livre"
        fmt_buttons = [
            InlineKeyboardButton("EPUB", callback_data=f"dlfmt_epub_{idx}") if "epub" in ALLOWED_FORMATS else None,
            InlineKeyboardButton("PDF", callback_data=f"dlfmt_pdf_{idx}") if "pdf" in ALLOWED_FORMATS else None,
        ]
        keyboard = InlineKeyboardMarkup([
            [b for b in fmt_buttons if b],
            [InlineKeyboardButton(_t(context, "cancel"), callback_data="cancel_dl")],
        ])
        await query.edit_message_text(
            _t(context, "choose_format", title=title[:60]),
            reply_markup=keyboard,
        )
        return

    to_pdf = result.get("ext") == "epub" and ALLOWED_FORMATS == ["pdf"]
    await _do_download(query, context, idx, to_pdf=to_pdf)


async def handle_download_fmt(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    query = update.callback_query
    await query.answer()

    if not _is_allowed(update):
        return

    m = re.match(r"^dlfmt_(epub|pdf)_(\d+)$", query.data or "")
    if not m:
        return

    fmt, idx = m.group(1), int(m.group(2))
    await _do_download(query, context, idx, to_pdf=(fmt == "pdf"))


async def _do_download(query, context: ContextTypes.DEFAULT_TYPE, idx: int, to_pdf: bool) -> None:
    results = context.user_data.get("results", [])
    if idx >= len(results):
        await query.edit_message_text(_t(context, "expired"))
        return

    def _progress_bar(pct: int) -> str:
        filled = pct // 10
        return "▰" * filled + "▱" * (10 - filled)

    async def _try_download(start_idx: int) -> tuple[str, dict] | None | str:
        any_mirror_failure = False
        for i in range(start_idx, len(results)):
            result = results[i]
            t = result.get("title") or "livre"
            ext = result.get("ext") or "epub"
            is_torrent = result.get("is_torrent", False)

            if i > start_idx:
                logger.info(f"Auto-retry on result {i}: {t!r}")
                await query.edit_message_text(_t(context, "retry", title=t), reply_markup=_cancel_kb(context))

            if is_torrent:
                await query.edit_message_text(
                    _t(context, "torrent_wait", title=t),
                    reply_markup=_cancel_kb(context),
                )
            else:
                await query.edit_message_text(_t(context, "preparing") + "…", reply_markup=_cancel_kb(context))

            streaming_started = asyncio.Event()
            dots_task = asyncio.create_task(_animate_preparing(query, context, streaming_started, reply_markup=_cancel_kb(context)))

            async def on_progress(downloaded: int, total: int, _t=t) -> None:
                if not streaming_started.is_set():
                    streaming_started.set()
                if total:
                    pct = min(int(downloaded / total * 100), 99)
                    bar = _progress_bar(pct)
                    await query.edit_message_text(
                        f"⬇️ « {_t} »\n{bar} {pct}%  ({_fmt_size(downloaded)} / {_fmt_size(total)})",
                        reply_markup=_cancel_kb(context),
                    )
                else:
                    await query.edit_message_text(
                        f"⬇️ « {_t} »\n{_fmt_size(downloaded)} téléchargés…",
                        reply_markup=_cancel_kb(context),
                    )

            dl_task = asyncio.create_task(
                downloader.download_result(result, progress_callback=None if is_torrent else on_progress, max_bytes=MAX_FILE_SIZE)
            )
            if is_torrent:
                while not dl_task.done():
                    await asyncio.sleep(30)
                    if not dl_task.done():
                        try:
                            await query.edit_message_text(
                                _t(context, "still_waiting", title=t),
                                reply_markup=_cancel_kb(context),
                            )
                        except Exception:
                            pass

            try:
                file_path = await dl_task
            except asyncio.CancelledError:
                dl_task.cancel()
                raise
            except TimeoutError:
                logger.warning(f"Timeout on result {i}, skipping")
                dots_task.cancel()
                any_mirror_failure = True
                continue
            except Exception as e:
                logger.warning(f"Result {i} failed ({e}), skipping")
                dots_task.cancel()
                any_mirror_failure = True
                continue
            finally:
                dots_task.cancel()

            size = os.path.getsize(file_path)
            if size > MAX_FILE_SIZE:
                logger.info(f"Result {i} too large ({_fmt_size(size)}), skipping")
                try:
                    os.remove(file_path)
                except Exception:
                    pass
                continue

            return file_path, result

        return "mirrors" if any_mirror_failure else None

    download_task = asyncio.create_task(_try_download(idx))
    context.user_data["active_dl_task"] = download_task
    try:
        outcome = await download_task
    except asyncio.CancelledError:
        return
    finally:
        context.user_data.pop("active_dl_task", None)

    if outcome is None or isinstance(outcome, str):
        if outcome == "mirrors":
            msg_text = _t(context, "mirrors_fail")
        else:
            msg_text = _t(context, "size_limit")
        await query.edit_message_text(msg_text)
        return

    file_path, result = outcome
    title = result.get("title") or "livre"
    ext = result.get("ext") or "epub"

    send_path = file_path
    send_ext = ext
    pdf_path = None

    try:
        safe_title = re.sub(r'[^\w\s\-]', '', title).strip()[:60] or "livre"
        filename = f"{safe_title}.{send_ext}"
        await query.edit_message_text(_t(context, "sending", title=title))

        with open(send_path, "rb") as f:
            await query.message.reply_document(
                document=f,
                filename=filename,
                caption=f"{title}",
            )

        await query.edit_message_text(_t(context, "done"))
    finally:
        for path in (file_path, pdf_path):
            if path and path.startswith(tempfile.gettempdir()):
                try:
                    os.remove(path)
                except Exception:
                    pass


async def handle_confirm_non_epub(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    query = update.callback_query
    await query.answer()
    if not _is_allowed(update):
        return
    results = context.user_data.get("results", [])
    if not results:
        await query.edit_message_text(_t(context, "expired"))
        return
    buttons = []
    for i, r in enumerate(results):
        title_short = (r.get("title") or "?")[:40]
        ext = r.get("ext") or "?"
        size = _fmt_size(r.get("size_bytes", 0))
        buttons.append([InlineKeyboardButton(f"{title_short} — {ext} — {size}", callback_data=f"dl_{i}")])
    await query.edit_message_text(
        _t(context, "choose_result"),
        reply_markup=InlineKeyboardMarkup(buttons),
    )


async def handle_cancel_download(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    query = update.callback_query
    await query.answer()
    if not _is_allowed(update):
        return
    task = context.user_data.pop("active_dl_task", None)
    if task and not task.done():
        task.cancel()
        await query.edit_message_text(_t(context, "dl_cancelled"))
    else:
        await query.edit_message_text(_t(context, "no_dl"))


async def handle_cancel_search(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    query = update.callback_query
    await query.answer()
    context.user_data.pop("results", None)
    await query.edit_message_text(_t(context, "search_cancelled"))


def main() -> None:
    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)

    builder = Application.builder().token(TELEGRAM_TOKEN)
    if LOCAL_API_SERVER:
        builder = (
            builder
            .base_url(f"{LOCAL_API_SERVER}/bot")
            .base_file_url(f"{LOCAL_API_SERVER}/file/bot")
            .local_mode(True)
        )
    app = builder.build()

    app.add_handler(CommandHandler("start", start))
    app.add_handler(CallbackQueryHandler(handle_language, pattern=r"^lang_(fr|en)$"))
    app.add_handler(MessageHandler(filters.TEXT & ~filters.COMMAND, handle_search))
    app.add_handler(CallbackQueryHandler(handle_download, pattern=r"^dl_\d+$"))
    app.add_handler(CallbackQueryHandler(handle_download_fmt, pattern=r"^dlfmt_(epub|pdf)_\d+$"))
    app.add_handler(CallbackQueryHandler(handle_confirm_non_epub, pattern=r"^confirm_non_epub$"))
    app.add_handler(CallbackQueryHandler(handle_cancel_search, pattern=r"^cancel_search$"))
    app.add_handler(CallbackQueryHandler(handle_cancel_download, pattern=r"^cancel_dl$"))

    if GITHUB_REPO:
        app.job_queue.run_repeating(check_for_updates, interval=86400, first=30)
        logger.info(f"Update checks enabled for {GITHUB_REPO} (every 24h)")

    _cleanup_orphaned_temp_files()

    logger.info(f"--- annas-bot v{VERSION} ---")
    logger.info(f"  Anna's Archive : {'✓ ' + os.environ.get('ANNA_ARCHIVE_URL', '') if os.environ.get('ANNA_ARCHIVE_URL') else '✗ désactivée'}")
    logger.info(f"  Prowlarr       : {'✓ ' + os.environ.get('PROWLARR_URL', '') if os.environ.get('PROWLARR_URL') else '✗ désactivé'}")
    logger.info(f"  Formats        : {', '.join(ALLOWED_FORMATS)}")
    logger.info(f"  VirusTotal     : {'✓ activé' if virustotal.VT_API_KEY else '✗ désactivé'}")
    logger.info(f"  Mises à jour   : {'✓ ' + GITHUB_REPO if GITHUB_REPO else '✗ désactivées'}")
    logger.info(f"  Limite fichier : {MAX_FILE_SIZE // 1024 // 1024} MB")
    logger.info(f"  Utilisateurs   : {len(ALLOWED_USER_IDS)} autorisé(s)")
    logger.info("Bot started.")
    app.run_polling(drop_pending_updates=True)


if __name__ == "__main__":
    main()
