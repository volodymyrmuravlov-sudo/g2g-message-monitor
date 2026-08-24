"""Check the G2G chat list for new/changed messages and alert via Telegram.

State (a SHA-256 hash per visible conversation row: name + last message +
time) is persisted to state.json in the repo, which the workflow commits
back after every run. Only hashes are stored - never the raw message text -
since this file lives in git history. Any row whose hash is new or changed
since the last run means a new message arrived in that conversation -
regardless of whether G2G moves it to the top of the list.
"""
import hashlib
import json
import os
import sys
from datetime import datetime, timezone
from pathlib import Path

import requests
from playwright.sync_api import sync_playwright

REPO_ROOT = Path(__file__).resolve().parent.parent
STATE_FILE = REPO_ROOT / "state.json"

INBOX_URL = os.environ.get("G2G_INBOX_URL", "https://www.g2g.com/chat/#/")

TELEGRAM_BOT_TOKEN = os.environ.get("TELEGRAM_BOT_TOKEN")
TELEGRAM_CHAT_ID = os.environ.get("TELEGRAM_CHAT_ID")

# Reads every conversation row currently rendered in the G2G chat sidebar.
# Row structure (confirmed from the live site):
#   .g-channel-item--main  -> contains sender name + last-message preview
#   .g-channel-item--side  -> contains the last-message timestamp
# Both are direct children of the same (unnamed) row wrapper.
FINGERPRINT_JS = """
() => Array.from(document.querySelectorAll('.g-channel-item--main')).map(mainEl => {
    const row = mainEl.parentElement;
    const side = row ? row.querySelector('.g-channel-item--side') : null;
    const name = row ? row.querySelector('.text-dark') : null;
    return {
        name: name ? name.innerText.trim() : '',
        text: mainEl.innerText.trim(),
        time: side ? side.innerText.trim() : '',
    };
})
"""


def load_state() -> dict:
    if STATE_FILE.exists():
        return json.loads(STATE_FILE.read_text(encoding="utf-8"))
    return {"known_fingerprints": [], "last_unread_counter": 0}


def save_state(state: dict) -> None:
    STATE_FILE.write_text(json.dumps(state, indent=2, ensure_ascii=False), encoding="utf-8")


def parse_cookie_editor_json(raw: str) -> list[dict]:
    """Convert a Cookie-Editor / EditThisCookie JSON export into Playwright cookie dicts."""
    exported = json.loads(raw)
    same_site_map = {
        "no_restriction": "None",
        "unspecified": "Lax",
        "lax": "Lax",
        "strict": "Strict",
        "none": "None",
    }
    cookies = []
    for c in exported:
        same_site_raw = str(c.get("sameSite", "lax")).lower()
        cookies.append({
            "name": c["name"],
            "value": c["value"],
            "domain": c["domain"],
            "path": c.get("path", "/"),
            "expires": c.get("expirationDate", -1) if not c.get("session") else -1,
            "httpOnly": c.get("httpOnly", False),
            "secure": c.get("secure", True),
            "sameSite": same_site_map.get(same_site_raw, "Lax"),
        })
    return cookies


def build_storage_state(cookies: list[dict], local_storage_raw: str) -> dict:
    """Combine Playwright cookies with a JSON.stringify(localStorage) dump into
    Playwright's native storage_state format, so the browser context looks
    fully logged in (G2G keeps its auth JWT in localStorage, not cookies)."""
    local_storage: dict = json.loads(local_storage_raw)
    return {
        "cookies": cookies,
        "origins": [
            {
                "origin": "https://www.g2g.com",
                "localStorage": [
                    {"name": k, "value": v} for k, v in local_storage.items()
                ],
            }
        ],
    }


def get_unread_counter(page) -> int | None:
    raw = page.evaluate("() => localStorage.getItem('chatUnread')")
    if not raw:
        return None
    try:
        return json.loads(raw).get("counter")
    except (json.JSONDecodeError, AttributeError):
        return None


def translate_to_uk(text: str) -> str:
    """Best-effort translation to Ukrainian via MyMemory's free public API
    (no key/signup needed, auto-detects source language). Falls back to the
    original text on any failure so a translation hiccup never blocks the
    alert."""
    if not text.strip():
        return text
    try:
        resp = requests.get(
            "https://api.mymemory.translated.net/get",
            params={"q": text[:490], "langpair": "autodetect|uk"},
            timeout=10,
        )
        resp.raise_for_status()
        data = resp.json()
        if data.get("responseStatus") != 200:
            return text
        translated = data["responseData"]["translatedText"]
        # MyMemory returns this exact phrase (not a translation) when the
        # detected source language is already Ukrainian - the text was
        # already in Ukrainian, so just keep it as-is.
        if translated.strip().upper() == "PLEASE SELECT TWO DISTINCT LANGUAGES":
            return text
        return translated
    except Exception as exc:
        print(f"WARNING: translation failed: {exc}")
        return text


def message_preview(row: dict) -> str:
    """The message-preview part of row['text'], without the sender name
    (which is joined in front of it via a newline in the DOM)."""
    parts = row["text"].split("\n", 1)
    return parts[1].strip() if len(parts) > 1 else row["text"]


def send_telegram(text: str) -> None:
    if not TELEGRAM_BOT_TOKEN or not TELEGRAM_CHAT_ID:
        print("Telegram secrets missing, skipping alert:", text)
        return
    resp = requests.post(
        f"https://api.telegram.org/bot{TELEGRAM_BOT_TOKEN}/sendMessage",
        json={"chat_id": TELEGRAM_CHAT_ID, "text": text},
        timeout=15,
    )
    resp.raise_for_status()


def get_conversation_rows(page) -> list[dict]:
    return page.evaluate(FINGERPRINT_JS)


def fingerprint(row: dict) -> str:
    # Deliberately excludes row["time"]: G2G's displayed date for a row is
    # recomputed on each render and can flip by a day between two checks
    # for the exact same message, which made stable old conversations look
    # "changed" for no real reason. Name + message text is what actually
    # identifies a distinct message.
    raw = f"{row['name']}|{row['text']}"
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()[:24]


def last_message_is_own(row: dict) -> bool:
    """True if the row's last-message preview is one you sent yourself
    (G2G prefixes it with 'Ви:' in this account's UI language) rather than
    an incoming message from the other side."""
    return message_preview(row).startswith(("Ви:", "You:"))


SYSTEM_ROW_NAME_MARKERS = ("g2g адмінstars", "g2g adminstars")
SYSTEM_ROW_TEXT_MARKERS = (
    "заблокували цього користувача",  # "you blocked this user"
    "blocked this user",
    "обліковий запис заблоковано",  # "account suspended"
    "account suspended",
    "ласкаво просимо!",  # G2G's own admin welcome message
    "welcome!",
)


def is_system_row(row: dict) -> bool:
    """True for G2G's own platform/admin rows (blocked-user notices, account
    status, the admin welcome message) - never real buyer conversations, and
    prone to flaky name/time scraping that causes false "changed" hits."""
    name = row["name"].strip().lower()
    if not name or name in SYSTEM_ROW_NAME_MARKERS:
        return True
    preview = message_preview(row).lower()
    return any(marker in preview for marker in SYSTEM_ROW_TEXT_MARKERS)


def main() -> int:
    cookies_raw = os.environ.get("G2G_COOKIES_JSON")
    local_storage_raw = os.environ.get("G2G_LOCAL_STORAGE_JSON")
    if not cookies_raw or not local_storage_raw:
        print("G2G_COOKIES_JSON / G2G_LOCAL_STORAGE_JSON secret is not set.", file=sys.stderr)
        return 1

    cookies = parse_cookie_editor_json(cookies_raw)
    storage_state = build_storage_state(cookies, local_storage_raw)
    state = load_state()
    known = set(state.get("known_fingerprints", []))
    last_counter = state.get("last_unread_counter", 0)

    with sync_playwright() as p:
        browser = p.chromium.launch(headless=True)
        # Pin the UI language to Ukrainian - without this, a fresh browser
        # context sometimes renders G2G in English instead (matching the
        # account's g2g_regional cookie), which made every row's text look
        # "changed" between runs and triggered false new-message alerts.
        context = browser.new_context(
            storage_state=storage_state,
            locale="uk-UA",
            extra_http_headers={"Accept-Language": "uk-UA,uk;q=0.9"},
        )
        page = context.new_page()
        page.goto(INBOX_URL, timeout=45000)
        page.wait_for_timeout(3000)

        print(f"DEBUG landed on: {page.url}")
        print(f"DEBUG title: {page.title()}")

        if "login" in page.url.lower() or "sign" in page.url.lower():
            send_telegram(
                "⚠️ G2G monitor: сессия истекла (редирект на страницу входа). "
                "Нужно обновить cookies и localStorage в GitHub Secrets."
            )
            browser.close()
            return 1

        counter = get_unread_counter(page)
        print(f"DEBUG chatUnread counter: {counter}")

        try:
            page.wait_for_selector(".g-channel-item--main", timeout=20000)
            rows = get_conversation_rows(page)
        except Exception:
            rows = []
            print("WARNING: conversation rows not found on page")

        browser.close()

    current_fps = {fingerprint(r): r for r in rows}
    changed_fps = set(current_fps) - known if rows else set()
    # Skip rows whose last message is one you sent yourself (e.g. replied
    # directly in G2G), and G2G's own system/admin rows (blocked-user
    # notices, account status, the admin welcome message) - neither is a
    # real incoming buyer message worth alerting on.
    new_fps = {
        fp for fp in changed_fps
        if not last_message_is_own(current_fps[fp]) and not is_system_row(current_fps[fp])
    }

    counter_increased = counter is not None and counter > last_counter

    print(
        f"Rows seen: {len(rows)}, changed: {len(changed_fps)}, "
        f"new (excluding own replies): {len(new_fps)}, counter increased: {counter_increased}"
    )

    if known and (counter_increased or new_fps):
        lines = []
        for fp in list(new_fps)[:5]:
            r = current_fps[fp]
            preview = message_preview(r)[:300]
            translated = translate_to_uk(preview)
            if translated.strip() == preview.strip():
                lines.append(f"{r['name']} ({r['time']}):\n{preview}")
            else:
                lines.append(f"{r['name']} ({r['time']}):\n{translated}\n(ориг.: {preview})")
        header = f"📩 G2G: новое сообщение! Непрочитано: {counter}" if counter is not None else "📩 G2G: новое сообщение!"
        body = "\n\n".join(lines) if lines else INBOX_URL
        send_telegram(f"{header}\n\n{body}")

    state["known_fingerprints"] = list(current_fps.keys()) if rows else state.get("known_fingerprints", [])
    if counter is not None:
        state["last_unread_counter"] = counter
    state["last_checked_utc"] = datetime.now(timezone.utc).isoformat(timespec="seconds")
    save_state(state)
    return 0


if __name__ == "__main__":
    sys.exit(main())
