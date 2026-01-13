from __future__ import annotations

import json
import hashlib
import html
import logging
import secrets
import shutil
import threading
import time
import webbrowser
import xml.etree.ElementTree as ET
from dataclasses import dataclass
from datetime import datetime, timezone
from email.utils import format_datetime
from http.server import BaseHTTPRequestHandler, HTTPServer, ThreadingHTTPServer
from pathlib import Path
from typing import Any
from urllib.parse import urlencode, urlparse, parse_qs

import requests
from requests.auth import HTTPBasicAuth

import re
from collections import defaultdict
from urllib.parse import quote, unquote




# ---------------- OAuth helpers ----------------

@dataclass
class OAuthConfig:
    authorization_endpoint: str
    token_endpoint: str


class CallbackState:
    def __init__(self) -> None:
        self.code: str | None = None
        self.error: str | None = None
        self.state: str | None = None
        self._evt = threading.Event()

    def set_result(self, code: str | None, error: str | None, state: str | None) -> None:
        self.code = code
        self.error = error
        self.state = state
        self._evt.set()

    def wait(self, timeout: int = 300) -> None:
        if not self._evt.wait(timeout=timeout):
            raise TimeoutError("Timed out waiting for OAuth redirect.")


def discover_oauth(server: str) -> OAuthConfig:
    url = server.rstrip("/") + "/Panopto/oauth2/.well-known/openid-configuration"
    r = requests.get(url, timeout=20)
    r.raise_for_status()
    data = r.json()
    return OAuthConfig(
        authorization_endpoint=data["authorization_endpoint"],
        token_endpoint=data["token_endpoint"],
    )


def run_callback_server(redirect_uri: str, cb_state: CallbackState) -> HTTPServer:
    parsed = urlparse(redirect_uri)
    host = parsed.hostname or "127.0.0.1"
    port = parsed.port or 8765
    path = parsed.path or "/callback"

    class Handler(BaseHTTPRequestHandler):
        def do_GET(self) -> None:
            if urlparse(self.path).path != path:
                self.send_response(404)
                self.end_headers()
                return
            q = parse_qs(urlparse(self.path).query)
            code = (q.get("code") or [None])[0]
            err = (q.get("error") or [None])[0]
            st = (q.get("state") or [None])[0]
            cb_state.set_result(code, err, st)

            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.end_headers()
            self.wfile.write(b"<html><body><p>OK. You can close this window.</p></body></html>")

        def log_message(self, fmt: str, *args) -> None:
            return

    httpd = HTTPServer((host, port), Handler)
    t = threading.Thread(target=httpd.serve_forever, daemon=True)
    t.start()
    return httpd


def load_json(path: Path) -> dict[str, Any] | None:
    if not path.exists():
        return None
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return None


def save_json(path: Path, data: dict[str, Any]) -> None:
    path.write_text(json.dumps(data, indent=2), encoding="utf-8")


def token_expired(token: dict[str, Any], skew_seconds: int = 60) -> bool:
    obtained_at = int(token.get("obtained_at", 0))
    expires_in = int(token.get("expires_in", 0))
    if not obtained_at or not expires_in:
        return True
    return time.time() > (obtained_at + expires_in - skew_seconds)


def get_access_token(
    server: str,
    client_id: str,
    client_secret: str,
    scope: str,
    redirect_uri: str,
    token_cache: Path,
    logger: logging.Logger,
) -> str:
    oauth = discover_oauth(server)

    token = load_json(token_cache) or {}
    if token.get("access_token") and not token_expired(token):
        return str(token["access_token"])

    # Refresh if possible
    if token.get("refresh_token"):
        logger.info("Refreshing token...")
        r = requests.post(
            oauth.token_endpoint,
            data={
                "grant_type": "refresh_token",
                "refresh_token": token["refresh_token"],
                "scope": scope,
            },
            auth=HTTPBasicAuth(client_id, client_secret),
            timeout=30,
        )
        if r.ok:
            new_tok = r.json()
            if "refresh_token" not in new_tok:
                new_tok["refresh_token"] = token["refresh_token"]
            new_tok["obtained_at"] = int(time.time())
            save_json(token_cache, new_tok)
            return str(new_tok["access_token"])
        logger.warning("Refresh failed (HTTP %s); interactive login needed.", r.status_code)

    # First-time interactive auth
    logger.info("Opening browser for Panopto login...")
    cb_state = CallbackState()
    expected_state = secrets.token_urlsafe(24)
    cb_state.state = expected_state

    httpd = run_callback_server(redirect_uri, cb_state)
    auth_url = oauth.authorization_endpoint + "?" + urlencode(
        {
            "client_id": client_id,
            "response_type": "code",
            "redirect_uri": redirect_uri,
            "scope": scope,
            "state": expected_state,
        }
    )
    webbrowser.open(auth_url)

    try:
        cb_state.wait(timeout=300)
    finally:
        httpd.shutdown()

    if cb_state.error:
        raise RuntimeError(f"OAuth error: {cb_state.error}")
    if not cb_state.code:
        raise RuntimeError("No authorization code returned.")
    if cb_state.state != expected_state:
        raise RuntimeError("OAuth state mismatch.")

    r = requests.post(
        oauth.token_endpoint,
        data={
            "grant_type": "authorization_code",
            "code": cb_state.code,
            "redirect_uri": redirect_uri,
        },
        auth=HTTPBasicAuth(client_id, client_secret),
        timeout=30,
    )
    r.raise_for_status()
    tok = r.json()
    tok["obtained_at"] = int(time.time())
    save_json(token_cache, tok)
    return str(tok["access_token"])


# ---------------- Panopto Subscriptions fetch (legacy Data.svc) ----------------

def ms_json_date_to_dt(val: Any) -> datetime | None:
    # Handles "/Date(1700000000000)/" style
    if not isinstance(val, str):
        return None
    if val.startswith("/Date(") and val.endswith(")/"):
        inner = val[len("/Date("):-len(")/")]
        try:
            millis = int(inner.split("+", 1)[0].split("-", 1)[0])
            return datetime.fromtimestamp(millis / 1000, tz=timezone.utc)
        except Exception:
            return None
    return None


def parse_dt(val: Any) -> datetime:
    if val is None:
        return datetime.now(timezone.utc)
    if isinstance(val, (int, float)):
        try:
            return datetime.fromtimestamp(float(val), tz=timezone.utc)
        except Exception:
            return datetime.now(timezone.utc)
    if isinstance(val, str):
        m = ms_json_date_to_dt(val)
        if m:
            return m
        try:
            if val.endswith("Z"):
                return datetime.fromisoformat(val.replace("Z", "+00:00"))
            return datetime.fromisoformat(val)
        except Exception:
            return datetime.now(timezone.utc)
    return datetime.now(timezone.utc)


# ---------------- Enrichment: folder paths + author ----------------

def _is_empty_guid(value: Any) -> bool:
    """True if value looks like an 'empty' GUID (all zeros) or is missing."""
    if not isinstance(value, str):
        return True
    s = value.strip().strip("{}")
    if not s:
        return True
    core = s.replace("-", "").lower()
    return bool(core) and set(core) == {"0"}


def _extract_author(session: dict[str, Any]) -> str | None:
    # Prefer explicit owner/creator fields when present.
    for key in (
        "OwnerFullName",
        "OwnerName",
        "Owner",
        "CreatedByFullName",
        "CreatedBy",
        "Creator",
        "Author",
        "author",
    ):
        v = session.get(key)
        if isinstance(v, str) and v.strip():
            return v.strip()

    # Fall back to presenter fields (often arrays).
    firsts = session.get("PresenterFirstNames")
    lasts = session.get("PresenterLastNames")
    if isinstance(firsts, list) and isinstance(lasts, list) and firsts and lasts and len(firsts) == len(lasts):
        names = [f"{f} {l}".strip() for f, l in zip(firsts, lasts)]
        names = [n for n in names if n]
        if names:
            return ", ".join(names)

    # Some payloads include a single presenter string.
    v = session.get("PresenterName") or session.get("Presenter") or session.get("presenter")
    if isinstance(v, str) and v.strip():
        return v.strip()

    return None


def _get_folder(
    sess: requests.Session,
    server: str,
    access_token: str,
    folder_id: str,
    logger: logging.Logger | None,
) -> dict[str, Any] | None:
    """GET /api/v1/folders/{id}. Returns None on 404."""
    url = f"{server.rstrip('/')}/Panopto/api/v1/folders/{folder_id}"
    headers = {"Authorization": f"Bearer {access_token}"}

    for attempt in range(3):
        resp = sess.get(url, headers=headers, timeout=30)
        if resp.status_code == 404:
            return None
        if resp.status_code in (429, 500, 502, 503, 504):
            time.sleep(0.5 * (attempt + 1))
            continue
        resp.raise_for_status()
        return resp.json()

    resp.raise_for_status()
    return None


def build_rss(server: str, items: list[dict[str, Any]], out_path: Path) -> None:
    # Include Dublin Core creator for author names.
    rss = ET.Element(
        "rss",
        attrib={
            "version": "2.0",
            "xmlns:dc": "http://purl.org/dc/elements/1.1/",
        },
    )
    channel = ET.SubElement(rss, "channel")

    ET.SubElement(channel, "title").text = "Panopto Subscriptions"
    ET.SubElement(channel, "link").text = server.rstrip("/") + "/Panopto/Pages/Sessions/List.aspx#isSubscriptionsPage=true"
    ET.SubElement(channel, "description").text = "Sessions from your Panopto Subscriptions tab"
    ET.SubElement(channel, "lastBuildDate").text = format_datetime(datetime.now(timezone.utc))

    for s in items:
        session_id = (s.get("SessionID") or s.get("Id") or s.get("id") or "").strip()
        title = (s.get("SessionName") or s.get("Name") or s.get("name") or "Untitled").strip()

        link = (
            s.get("ViewerUrl")
            or s.get("ViewerURL")
            or s.get("Url")
            or s.get("url")
            or (server.rstrip("/") + f"/Panopto/Pages/Viewer.aspx?id={session_id}" if session_id else server.rstrip("/") + "/Panopto")
        )

        guid = session_id or link

        dt = parse_dt(
            s.get("StartTime")
            or s.get("CreatedDate")
            or s.get("createdDate")
            or s.get("CreatedOn")
            or s.get("LastModified")
            or s.get("LastModifiedDate")
        )

        folder_path = s.get("FolderPath") or s.get("FolderName") or s.get("folderName")
        author = s.get("Author") or s.get("OwnerFullName") or s.get("Owner") or s.get("Creator")

        abstract = s.get("SessionAbstract") or s.get("Description") or s.get("description") or ""
        author_txt = author.strip() if isinstance(author, str) else ""
        folder_txt = folder_path.strip() if isinstance(folder_path, str) else ""
        folder_txt = folder_txt.replace(" / ", " › ") if folder_txt else ""
        abstract_txt = abstract.strip() if isinstance(abstract, str) else ""

        lines: list[str] = []
        if author_txt:
            lines.append(f"<b>Author:</b> {html.escape(author_txt)}")
        if folder_txt:
            lines.append(f"<b>Folder:</b> {html.escape(folder_txt)}")

        description = "<br/>".join(lines)
        if abstract_txt:
            description = (description + "<br/><br/>" if description else "") + html.escape(abstract_txt)

        item = ET.SubElement(channel, "item")
        ET.SubElement(item, "title").text = title
        ET.SubElement(item, "link").text = str(link)
        ET.SubElement(item, "guid").text = guid
        ET.SubElement(item, "pubDate").text = format_datetime(dt)

        if isinstance(author, str) and author.strip():
            ET.SubElement(item, "{http://purl.org/dc/elements/1.1/}creator").text = author.strip()

        if isinstance(folder_path, str) and folder_path.strip():
            ET.SubElement(item, "category").text = folder_path.strip()

        if description:
            ET.SubElement(item, "description").text = description

    out_path.parent.mkdir(parents=True, exist_ok=True)
    ET.ElementTree(rss).write(out_path, encoding="utf-8", xml_declaration=True)


def fetch_subscriptions_sessions(
    server: str,
    access_token: str,
    max_results_per_page: int,
    max_items: int,
    logger: logging.Logger,
) -> list[dict[str, Any]]:
    """
    Fetches the same sessions shown in Panopto's Subscriptions tab by:
      1) Calling /api/v1/auth/legacyLogin to mint legacy cookies
      2) Calling /Services/Data.svc/GetSessions with isSubscriptionsPage=true
    """
    server = server.rstrip("/")
    sess = requests.Session()

    # 1) OAuth token -> legacy auth cookie
    legacy_login_url = f"{server}/Panopto/api/v1/auth/legacyLogin"
    r = sess.get(
        legacy_login_url,
        headers={"Authorization": f"Bearer {access_token}"},
        timeout=30,
        allow_redirects=True,
    )
    r.raise_for_status()

    # 2) Prime cookies + csrf token by visiting the subscriptions page
    subs_page = (
        f"{server}/Panopto/Pages/Sessions/List.aspx"
        f"?embedded=0&isFromTeams=false"
        f"#isSubscriptionsPage=true"
    )
    r = sess.get(subs_page, timeout=30, allow_redirects=True)
    r.raise_for_status()

    csrf = sess.cookies.get("csrfToken") or sess.cookies.get("XSRF-TOKEN")

    url = f"{server}/Panopto/Services/Data.svc/GetSessions"
    headers = {
        "Accept": "application/json, text/javascript, */*; q=0.01",
        "Content-Type": "application/json; charset=UTF-8",
        "X-Requested-With": "XMLHttpRequest",
        "Referer": subs_page,
        "Origin": server,
        "User-Agent": "Mozilla/5.0",
    }
    if csrf:
        headers["X-CSRFToken"] = csrf
        headers["X-CSRF-Token"] = csrf  # some tenants check this name instead

    results: list[dict[str, Any]] = []
    page = 0

    # Try a few payload variants (Panopto tenants differ)
    def payload_variant(get_folder_data: bool | None, include_playlists: bool | None) -> dict[str, Any]:
        qp: dict[str, Any] = {
            "query": None,
            "startDate": None,
            "endDate": None,
            "sortColumn": 1,
            "sortAscending": False,
            "maxResults": max_results_per_page,
            "page": page,
            "bookmarked": False,
            "isSharedWithMe": False,
            "isSubscriptionsPage": True,
            "includeArchived": False,
            "folderID": None,
            "subscribableTypes": [0, 1, 2],
        }
        if get_folder_data is not None:
            qp["getFolderData"] = get_folder_data
        if include_playlists is not None:
            qp["includePlaylists"] = include_playlists
        return {"queryParameters": qp}

    variants = [
        payload_variant(True, True),
        payload_variant(False, True),
        payload_variant(False, None),
    ]

    while len(results) < max_items:
        # update page/maxResults in all variants
        for v in variants:
            v["queryParameters"]["page"] = page
            v["queryParameters"]["maxResults"] = max_results_per_page

        last_err = None
        page_items: list[dict[str, Any]] | None = None

        for v in variants:
            resp = sess.post(url, headers=headers, json=v, timeout=30)
            if resp.status_code == 200:
                data = resp.json()
                d = data.get("d", data)
                page_items = (d.get("Results") if isinstance(d, dict) else None) or []
                break

            last_err = (resp.status_code, resp.text[:2000])
            time.sleep(0.2)

        if page_items is None:
            code, body = last_err if last_err else ("?", "")
            raise RuntimeError(
                f"GetSessions failed. Last status={code}. Body (first 2000 chars):\n{body}"
            )

        if not page_items:
            break

        results.extend(page_items)

        if logger:
            logger.info("Subscriptions page %s: %s items (total %s)", page, len(page_items), len(results))

        if len(page_items) < max_results_per_page:
            break

        page += 1

    return results[:max_items]


_INVALID_FS_CHARS = re.compile(r'[<>:"/\\|?*\x00-\x1F]')


def sanitize_fs_segment(name: str) -> str:
    # Windows-safe folder/file segment
    s = _INVALID_FS_CHARS.sub("_", name).strip()
    s = s.rstrip(". ")  # Windows forbids trailing dot/space
    return s or "_"


def _utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _atomic_write_bytes(path: Path, data: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(path.suffix + ".tmp")
    tmp.write_bytes(data)
    tmp.replace(path)


def _atomic_write_text(path: Path, text: str) -> None:
    _atomic_write_bytes(path, text.encode("utf-8"))


def _session_fields_for_signature(s: dict[str, Any]) -> tuple[str, str, str]:
    session_id = str((s.get("SessionID") or s.get("Id") or s.get("id") or "")).strip()
    title = str((s.get("SessionName") or s.get("Name") or s.get("name") or "")).strip()
    dt = parse_dt(
        s.get("LastModified")
        or s.get("LastModifiedDate")
        or s.get("StartTime")
        or s.get("CreatedDate")
        or s.get("createdDate")
        or s.get("CreatedOn")
    )
    return (session_id, dt.isoformat(), title)


def compute_folder_signature(items: list[dict[str, Any]]) -> str:
    rows = [_session_fields_for_signature(s) for s in items]
    rows.sort()
    payload = "\n".join("\t".join(r) for r in rows).encode("utf-8")
    return hashlib.sha1(payload).hexdigest()


def _delete_dir_tree(path: Path) -> None:
    if path.exists():
        shutil.rmtree(path, ignore_errors=True)


def _prune_empty_parents(start: Path, stop_at: Path) -> None:
    # Remove empty directories up to (but not including) stop_at
    cur = start
    stop_at = stop_at.resolve()
    while True:
        try:
            cur_r = cur.resolve()
        except Exception:
            break
        if cur_r == stop_at:
            break
        if not cur.exists() or not cur.is_dir():
            break
        try:
            next(cur.iterdir())
            break  # not empty
        except StopIteration:
            pass
        except Exception:
            break
        try:
            cur.rmdir()
        except Exception:
            break
        cur = cur.parent


@dataclass
class FolderMeta:
    folder_id: str
    name: str
    parent_id: str
    fetched_at_utc: str
    missing: bool = False


class FolderCache:
    def __init__(self, path: Path, ttl_days: int, logger: logging.Logger) -> None:
        self.path = path
        self.ttl_seconds = max(1, int(ttl_days)) * 86400
        self.logger = logger
        self._cache: dict[str, FolderMeta] = {}
        self._dirty = False

        raw = load_json(path) or {}
        for fid, v in (raw.get("folders") or {}).items():
            if not isinstance(v, dict):
                continue
            self._cache[fid] = FolderMeta(
                folder_id=fid,
                name=str(v.get("name") or ""),
                parent_id=str(v.get("parent_id") or ""),
                fetched_at_utc=str(v.get("fetched_at_utc") or ""),
                missing=bool(v.get("missing") or False),
            )

    def save_if_dirty(self) -> None:
        if not self._dirty:
            return
        payload = {
            "folders": {
                fid: {
                    "name": m.name,
                    "parent_id": m.parent_id,
                    "fetched_at_utc": m.fetched_at_utc,
                    "missing": m.missing,
                }
                for fid, m in self._cache.items()
            }
        }
        _atomic_write_text(self.path, json.dumps(payload, indent=2))
        self._dirty = False

    def _is_fresh(self, meta: FolderMeta) -> bool:
        if not meta.fetched_at_utc:
            return False
        try:
            t = datetime.fromisoformat(meta.fetched_at_utc)
            if t.tzinfo is None:
                t = t.replace(tzinfo=timezone.utc)
            age = (datetime.now(timezone.utc) - t).total_seconds()
            return age < self.ttl_seconds
        except Exception:
            return False

    def get(self, folder_id: str) -> FolderMeta | None:
        return self._cache.get(folder_id)

    def get_or_fetch(self, sess: requests.Session, server: str, access_token: str, folder_id: str) -> FolderMeta:
        folder_id = (folder_id or "").strip()
        if not folder_id or _is_empty_guid(folder_id):
            return FolderMeta(folder_id="", name="", parent_id="", fetched_at_utc=_utc_now_iso(), missing=True)

        existing = self._cache.get(folder_id)
        if existing and self._is_fresh(existing):
            return existing

        folder = _get_folder(sess, server, access_token, folder_id, self.logger)
        if not folder:
            meta = FolderMeta(
                folder_id=folder_id,
                name=f"Unknown folder ({folder_id})",
                parent_id="",
                fetched_at_utc=_utc_now_iso(),
                missing=True,
            )
            self._cache[folder_id] = meta
            self._dirty = True
            return meta

        name = str(folder.get("Name") or "").strip() or f"Folder {folder_id}"
        parent = folder.get("ParentFolder")
        parent_id = ""
        if isinstance(parent, dict):
            pid = parent.get("Id")
            if isinstance(pid, str) and not _is_empty_guid(pid):
                parent_id = pid.strip()

        meta = FolderMeta(folder_id=folder_id, name=name, parent_id=parent_id, fetched_at_utc=_utc_now_iso(), missing=False)
        self._cache[folder_id] = meta
        self._dirty = True
        return meta

    def ensure_with_ancestors(self, sess: requests.Session, server: str, access_token: str, folder_ids: set[str]) -> dict[str, FolderMeta]:
        queue = [fid for fid in folder_ids if fid and not _is_empty_guid(fid)]
        seen: set[str] = set()
        while queue:
            fid = queue.pop()
            if fid in seen:
                continue
            seen.add(fid)
            meta = self.get_or_fetch(sess, server, access_token, fid)
            if meta.parent_id and not _is_empty_guid(meta.parent_id):
                queue.append(meta.parent_id)
        return {fid: self._cache[fid] for fid in seen if fid in self._cache}


class StateStore:
    def __init__(self, path: Path) -> None:
        self.path = path
        raw = load_json(path) or {}
        self.folder_signatures: dict[str, str] = dict(raw.get("folder_signatures") or {})
        self.folder_output_paths: dict[str, str] = dict(raw.get("folder_output_paths") or {})
        self.last_refresh_utc: str = str(raw.get("last_refresh_utc") or "")
        self.last_error: str = str(raw.get("last_error") or "")
        self.last_error_utc: str = str(raw.get("last_error_utc") or "")
        self.last_counts: dict[str, int] = dict(raw.get("last_counts") or {})

    def save(self) -> None:
        payload = {
            "folder_signatures": self.folder_signatures,
            "folder_output_paths": self.folder_output_paths,
            "last_refresh_utc": self.last_refresh_utc,
            "last_error": self.last_error,
            "last_error_utc": self.last_error_utc,
            "last_counts": self.last_counts,
        }
        _atomic_write_text(self.path, json.dumps(payload, indent=2))


def _extract_folder_id(session: dict[str, Any]) -> str:
    fid = session.get("FolderID") or session.get("FolderId") or session.get("folderId") or ""
    return fid.strip() if isinstance(fid, str) else ""


def _build_children_map(metas: dict[str, FolderMeta]) -> dict[str, list[str]]:
    children: dict[str, list[str]] = defaultdict(list)
    for fid, meta in metas.items():
        parent_id = meta.parent_id or ""
        children[parent_id].append(fid)
    return children


def _assign_unique_fs_segments(
    metas: dict[str, FolderMeta],
    pinned_last_segments: dict[str, str] | None = None,
) -> dict[str, str]:
    pinned_last_segments = pinned_last_segments or {}
    children: dict[str, list[str]] = defaultdict(list)
    for fid, meta in metas.items():
        children[meta.parent_id or ""].append(fid)

    fs_seg: dict[str, str] = {}

    def sort_key(cid: str) -> tuple[str, str]:
        nm = (metas.get(cid).name if metas.get(cid) else "").lower()
        return (nm, cid)

    for parent_id, child_ids in children.items():
        used: set[str] = set()

        # 1) First: keep whatever segment we used last time for a folder id (prevents renames)
        for cid in child_ids:
            prev = pinned_last_segments.get(cid)
            if prev:
                seg = sanitize_fs_segment(prev)
                if seg not in used:
                    fs_seg[cid] = seg
                    used.add(seg)

        # 2) Then: assign remaining children deterministically
        for cid in sorted(child_ids, key=sort_key):
            if cid in fs_seg:
                continue

            meta = metas.get(cid)
            base = sanitize_fs_segment(meta.name if meta else cid)
            seg = base

            if seg in used:
                i = 2
                while f"{base}_{i}" in used:
                    i += 1
                seg = f"{base}_{i}"

            fs_seg[cid] = seg
            used.add(seg)

    return fs_seg


def _resolve_chain_ids(metas: dict[str, FolderMeta], folder_id: str) -> list[str]:
    # Returns ids from root->leaf within the known meta set.
    out: list[str] = []
    seen: set[str] = set()
    cur = folder_id
    while cur and cur not in seen and cur in metas:
        seen.add(cur)
        out.append(cur)
        parent_id = metas[cur].parent_id
        if not parent_id or _is_empty_guid(parent_id) or parent_id not in metas:
            break
        cur = parent_id
    return list(reversed(out))


def _build_index_html(
    title: str,
    feed_nodes: list[dict[str, Any]],
    base_url: str,
    last_updated: datetime,
) -> str:
    # feed_nodes: [{"id":..., "name":..., "children":[...], "feed_url":..., "count":...}]
    def render_node(n: dict[str, Any]) -> str:
        name = html.escape(str(n.get("name") or ""))
        count = int(n.get("count") or 0)
        feed_url = n.get("feed_url")
        has_feed = bool(feed_url)
        feed_html = ""
        if has_feed:
            fu = html.escape(str(feed_url))
            feed_html = f'<span class="links"><a class="btn" href="{fu}">Open feed</a><button class="btn" data-copy="{fu}">Copy URL</button></span>'

        children = n.get("children") or []
        children_html = "".join(render_node(c) for c in children)

        if children_html:
            return (
                f'<details class="node" open>'
                f'<summary><span class="name">{name}</span> <span class="count">{count}</span> {feed_html}</summary>'
                f'<div class="children">{children_html}</div>'
                f'</details>'
            )
        return (
            f'<div class="leaf node">'
            f'<div class="leafrow"><span class="name">{name}</span> <span class="count">{count}</span> {feed_html}</div>'
            f'</div>'
        )

    nodes_html = "".join(render_node(n) for n in feed_nodes)
    t = html.escape(title)
    bu = html.escape(base_url.rstrip("/"))

    lu_local = last_updated.astimezone()
    lu_iso = lu_local.isoformat(timespec="seconds")
    lu_disp = lu_local.strftime("%d %b %Y %H:%M:%S %Z").strip()
    return f"""<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  <title>{t}</title>
  <style>
    :root {{ color-scheme: light dark; }}
    body {{ margin: 0; font-family: system-ui, -apple-system, Segoe UI, Roboto, sans-serif; line-height: 1.35; }}
    header {{
      position: sticky;
      top: 0;
      backdrop-filter: blur(6px);
      padding: 12px 16px;
      border-bottom: 1px solid #9995;
      display: flex;
      flex-direction: column;
      align-items: center;
      text-align: center;
    }}
    header > * {{ width: 100%; max-width: 1100px; }}
    h1 {{ margin: 0 0 8px 0; font-size: 18px; text-align: center; }}
    .sub {{ font-size: 12px; opacity: 0.8; }}
    
    .actions {{
      margin-top: 8px;
      display: flex;
      gap: 8px;
      align-items: center;
      flex-wrap: wrap;
      justify-content: center;
    }}
    .danger {{ font-weight: 600; }}
    .status {{ font-size: 12px; opacity: 0.85; }}

    .search {{
      width: 100%;
      max-width: 760px;
      margin: 0 auto;
      padding: 10px 12px;
      border: 1px solid #9997;
      border-radius: 10px;
      font-size: 14px;
    }}
    
    main {{ padding: 12px 16px 60px; max-width: 1100px; margin: 0 auto; }}
    .node {{ margin: 8px 0; }}
    details.node > summary {{ cursor: pointer; list-style: none; display: flex; gap: 10px; align-items: center; padding: 10px 12px; border: 1px solid #9995; border-radius: 12px; }}
    details.node[open] > summary {{ border-bottom-left-radius: 0; border-bottom-right-radius: 0; }}
    .children {{ padding: 10px 12px; border: 1px solid #9995; border-top: 0; border-bottom-left-radius: 12px; border-bottom-right-radius: 12px; }}
    .leafrow {{ display: flex; gap: 10px; align-items: center; padding: 10px 12px; border: 1px solid #9995; border-radius: 12px; }}
    .name {{ flex: 1; min-width: 0; word-break: break-word; }}
    .count {{ font-size: 12px; opacity: 0.7; padding: 2px 8px; border: 1px solid #9995; border-radius: 999px; }}
    .links {{ display: inline-flex; gap: 8px; flex-wrap: wrap; }}
    .btn {{ font-size: 12px; padding: 6px 10px; border-radius: 10px; border: 1px solid #9997; text-decoration: none; background: transparent; cursor: pointer; }}
    .btn:active {{ transform: translateY(1px); }}
    .hint {{ margin-top: 10px; font-size: 12px; opacity: 0.8; text-align: center; }}
    @media (max-width: 520px) {{
      details.node > summary, .leafrow {{ flex-direction: column; align-items: stretch; }}
      .links {{ justify-content: flex-start; }}
    }}
  </style>
</head>
<body>
  <header>
    <h1>{t}</h1>
    <input id="q" class="search" placeholder="Filter folders…" autocomplete="off" />
    <div class="hint">
      Base URL: <code>{bu}</code> ·
      Last refreshed: <time datetime="{lu_iso}">{html.escape(lu_disp)}</time> ·
      Tip: open a feed once to subscribe; new folders appear here after refresh.
    </div>
    <div class="actions">
      <button id="refreshNow" class="btn" type="button">Refresh now</button>
      <button id="stopServer" class="btn danger" type="button">Stop server</button>
      <span id="actionStatus" class="status"></span>
    </div>
  </header>
  <main id="tree">{nodes_html}</main>
  <script>
    const q = document.getElementById('q');
    const tree = document.getElementById('tree');
    function textOf(el) {{ return (el.textContent || '').toLowerCase(); }}
    function apply() {{
      const term = (q.value || '').trim().toLowerCase();
      const nodes = tree.querySelectorAll('.node');
      nodes.forEach(n => {{
        const hit = !term || textOf(n).includes(term);
        n.style.display = hit ? '' : 'none';
      }});
    }}
    q.addEventListener('input', apply);
    document.addEventListener('click', (e) => {{
      const btn = e.target.closest('button[data-copy]');
      if (!btn) return;
      navigator.clipboard.writeText(btn.getAttribute('data-copy'));
      btn.textContent = 'Copied';
      setTimeout(() => btn.textContent = 'Copy URL', 900);
    }});
    
    const refreshBtn = document.getElementById('refreshNow');
    const stopBtn = document.getElementById('stopServer');
    const statusEl = document.getElementById('actionStatus');

    async function call(path) {{
      try {{
        const sep = path.includes('?') ? '&' : '?';
        return await fetch(path + sep + 'ts=' + Date.now(), {{ cache: 'no-store' }});
      }} catch (e) {{
        return null;
      }}
    }}

    if (refreshBtn) {{
      refreshBtn.addEventListener('click', async () => {{
        refreshBtn.disabled = true;
        if (statusEl) statusEl.textContent = 'Refreshing...';
        const r = await call('/refresh');
        if (r && r.ok) {{
          window.location.href = '/index.html?ts=' + Date.now();
        }} else {{
          if (statusEl) statusEl.textContent = 'Refresh failed';
          refreshBtn.disabled = false;
        }}
      }});
    }}

    if (stopBtn) {{
      stopBtn.addEventListener('click', async () => {{
        if (!confirm('Stop the Panopto RSS server?')) return;
        stopBtn.disabled = true;
        if (statusEl) statusEl.textContent = 'Stopping...';
        await call('/shutdown');
        if (statusEl) statusEl.textContent = 'Stopped';
      }});
    }}
  </script>
</body>
</html>"""


def _write_text_if_changed(path: Path, text: str) -> bool:
    data = text.encode("utf-8")
    if path.exists():
        try:
            if path.read_bytes() == data:
                return False
        except Exception:
            pass
    _atomic_write_bytes(path, data)
    return True


def build_rss_custom(server: str, items: list[dict[str, Any]], out_path: Path, channel_title: str) -> None:
    # Per-folder RSS feed. (Writes only when caller decides content changed.)
    rss = ET.Element(
        "rss",
        attrib={
            "version": "2.0",
            "xmlns:dc": "http://purl.org/dc/elements/1.1/",
        },
    )
    channel = ET.SubElement(rss, "channel")

    ET.SubElement(channel, "title").text = channel_title
    ET.SubElement(channel, "link").text = server.rstrip("/") + "/Panopto/Pages/Sessions/List.aspx#isSubscriptionsPage=true"
    ET.SubElement(channel, "description").text = f"Panopto sessions for: {channel_title}"
    ET.SubElement(channel, "lastBuildDate").text = format_datetime(datetime.now(timezone.utc))

    for s in items:
        session_id = (s.get("SessionID") or s.get("Id") or s.get("id") or "").strip()
        title = (s.get("SessionName") or s.get("Name") or s.get("name") or "Untitled").strip()

        link = (
            s.get("ViewerUrl")
            or s.get("ViewerURL")
            or s.get("Url")
            or s.get("url")
            or (server.rstrip("/") + f"/Panopto/Pages/Viewer.aspx?id={session_id}" if session_id else server.rstrip("/") + "/Panopto")
        )

        guid = session_id or link

        dt = parse_dt(
            s.get("StartTime")
            or s.get("CreatedDate")
            or s.get("createdDate")
            or s.get("CreatedOn")
            or s.get("LastModified")
            or s.get("LastModifiedDate")
        )

        author = (
            s.get("Author")
            or s.get("OwnerFullName")
            or s.get("Owner")
            or s.get("Creator")
            or _extract_author(s)
        )

        abstract = s.get("SessionAbstract") or s.get("Description") or s.get("description") or ""
        abstract = abstract.strip() if isinstance(abstract, str) else ""

        item = ET.SubElement(channel, "item")
        ET.SubElement(item, "title").text = title
        ET.SubElement(item, "link").text = str(link)
        ET.SubElement(item, "guid").text = guid
        ET.SubElement(item, "pubDate").text = format_datetime(dt)

        if isinstance(author, str) and author.strip():
            ET.SubElement(item, "{http://purl.org/dc/elements/1.1/}creator").text = author.strip()

        # Render as simple HTML so RSS readers don't collapse newlines.
        author_txt = author.strip() if isinstance(author, str) else ""
        folder_txt = channel_title.replace(" / ", " › ")

        lines: list[str] = []
        if author_txt:
            lines.append(f"<b>Author:</b> {html.escape(author_txt)}")
        lines.append(f"<b>Folder:</b> {html.escape(folder_txt)}")

        desc = "<br/>".join(lines)
        if abstract:
            desc += "<br/><br/>" + html.escape(abstract)

        ET.SubElement(item, "description").text = desc

        ET.SubElement(item, "category").text = channel_title

    out_path.parent.mkdir(parents=True, exist_ok=True)
    try:
        ET.indent(rss, space="  ")
    except AttributeError:
        pass

    ET.ElementTree(rss).write(out_path, encoding="utf-8", xml_declaration=True)


def build_folder_feeds_and_index(
    *,
    server: str,
    sessions: list[dict[str, Any]],
    folder_cache: FolderCache,
    state: StateStore,
    subscriptions_dir: Path,
    subscriptions_root_name: str,
    base_url: str,
    index_path: Path,
    feeds_json_path: Path | None,
    access_token: str,
    logger: logging.Logger,
) -> dict[str, int]:
    """Folder-ID-driven tree + per-folder feed files + index.html.

    Policy: only generate feeds for folders that contain sessions (FolderID present in results).
    """
    sess = requests.Session()

    # Group sessions by FolderID.
    sessions_by_folder: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for s in sessions:
        fid = _extract_folder_id(s)
        if fid and not _is_empty_guid(fid):
            sessions_by_folder[fid].append(s)

    leaf_folder_ids = set(sessions_by_folder.keys())

    metas = folder_cache.ensure_with_ancestors(sess, server, access_token, leaf_folder_ids)

    prior_paths = dict(state.folder_output_paths)
    pinned_last = {
        fid: Path(rel).name
        for fid, rel in prior_paths.items()
        if isinstance(rel, str) and rel
    }

    fs_seg_by_id = _assign_unique_fs_segments(metas, pinned_last)

    def display_path_for(fid: str) -> str:
        chain = _resolve_chain_ids(metas, fid)
        names = [metas[cid].name for cid in chain if cid in metas]
        return " / ".join([subscriptions_root_name] + [n for n in names if n])

    def rel_dir_for(fid: str) -> Path:
        chain = _resolve_chain_ids(metas, fid)
        segs = [fs_seg_by_id.get(cid) or sanitize_fs_segment(metas[cid].name) for cid in chain if cid in metas]
        return Path(*[s for s in segs if s])

    prior_sigs = dict(state.folder_signatures)
    wrote = 0
    skipped = 0

    feed_index: list[dict[str, Any]] = []

    # 3) Write feeds incrementally (signature-gated).
    for fid, items in sessions_by_folder.items():
        rel_dir = rel_dir_for(fid)
        rel_str = str(rel_dir).replace("\\", "/")
        out_dir = subscriptions_dir / rel_dir
        out_file = out_dir / "feed.xml"

        # Move/cleanup if folder moved/renamed.
        old_rel = prior_paths.get(fid)
        if old_rel and old_rel != rel_str:
            old_dir = subscriptions_dir / Path(old_rel)
            if old_dir.exists() and old_dir.is_dir() and old_dir != out_dir:
                try:
                    out_dir.parent.mkdir(parents=True, exist_ok=True)
                    shutil.move(str(old_dir), str(out_dir))
                except Exception:
                    _delete_dir_tree(old_dir)
                _prune_empty_parents(old_dir.parent, subscriptions_dir)

        sig = compute_folder_signature(items)
        old_sig = prior_sigs.get(fid)
        if (sig != old_sig) or (not out_file.exists()):
            build_rss_custom(server, items, out_file, channel_title=display_path_for(fid))
            wrote += 1
        else:
            skipped += 1

        state.folder_signatures[fid] = sig
        state.folder_output_paths[fid] = rel_str

        # Feed URL
        rel_url = "/".join(quote(p, safe="") for p in rel_str.split("/") if p)
        feed_url = f"{base_url.rstrip('/')}/subscriptions/{rel_url}/feed.xml" if rel_url else f"{base_url.rstrip('/')}/subscriptions/feed.xml"
        feed_index.append(
            {
                "folder_id": fid,
                "name": metas.get(fid).name if fid in metas else fid,
                "display_path": display_path_for(fid),
                "count": len(items),
                "feed_url": feed_url,
                "rel_dir": rel_str,
            }
        )

    # 4) Delete folders that disappeared.
    removed = set(prior_paths.keys()) - leaf_folder_ids
    for fid in removed:
        rel = prior_paths.get(fid)
        if not rel:
            continue
        dead_dir = subscriptions_dir / Path(rel)
        _delete_dir_tree(dead_dir)
        _prune_empty_parents(dead_dir.parent, subscriptions_dir)
        state.folder_signatures.pop(fid, None)
        state.folder_output_paths.pop(fid, None)

    # 5) Index tree: include ancestors but only leaf nodes have feeds.
    visible_ids: set[str] = set()
    for fid in leaf_folder_ids:
        visible_ids.update(_resolve_chain_ids(metas, fid))

    children_map = _build_children_map({fid: m for fid, m in metas.items() if fid in visible_ids})

    feed_url_by_id = {m["folder_id"]: m["feed_url"] for m in feed_index}
    count_by_id = {m["folder_id"]: int(m["count"]) for m in feed_index}

    def build_node(fid: str) -> dict[str, Any]:
        meta = metas.get(fid)
        kids = [c for c in children_map.get(fid, []) if c in visible_ids]
        kids_sorted = sorted(kids, key=lambda cid: (metas.get(cid).name.lower() if metas.get(cid) else "", cid))
        return {
            "id": fid,
            "name": meta.name if meta else fid,
            "count": count_by_id.get(fid, 0),
            "feed_url": feed_url_by_id.get(fid),
            "children": [build_node(c) for c in kids_sorted],
        }

    # Roots: nodes whose parent isn't visible or is empty.
    roots = []
    for fid in sorted(visible_ids, key=lambda cid: (metas.get(cid).name.lower() if metas.get(cid) else "", cid)):
        parent = metas.get(fid).parent_id if metas.get(fid) else ""
        if (not parent) or _is_empty_guid(parent) or (parent not in visible_ids):
            roots.append(fid)

    roots_nodes = [build_node(fid) for fid in roots]
    html_text = _build_index_html(
        "Panopto Subscriptions Feeds",
        roots_nodes,
        base_url=base_url,
        last_updated=datetime.now().astimezone(),
    )
    _write_text_if_changed(index_path, html_text)

    if feeds_json_path is not None:
        _write_text_if_changed(feeds_json_path, json.dumps({"feeds": feed_index}, indent=2))

    counts = {
        "sessions": len(sessions),
        "folders": len(leaf_folder_ids),
        "feeds_written": wrote,
        "feeds_skipped": skipped,
        "feeds_deleted": len(removed),
    }
    logger.info(
        "Folder feeds: %s folders (written=%s skipped=%s deleted=%s)",
        counts["folders"],
        counts["feeds_written"],
        counts["feeds_skipped"],
        counts["feeds_deleted"],
    )
    return counts


# ---------------- Server app ----------------

class FeedApp:
    def __init__(self, config_path: Path) -> None:
        self.config_path = config_path
        self.cfg = json.loads(config_path.read_text(encoding="utf-8"))
        self.base_dir = config_path.parent.resolve()

        self.server = self.cfg["server"].rstrip("/")
        self.client_id = self.cfg["client_id"]
        self.client_secret = self.cfg["client_secret"]
        self.scope = self.cfg.get("scope", "api")
        self.redirect_uri = self.cfg.get("redirect_uri", "http://127.0.0.1:8765/callback")

        self.port = int(self.cfg.get("port", 8080))
        self.refresh_minutes = int(self.cfg.get("refresh_minutes", 15))
        self.min_refresh_interval_seconds = int(
            self.cfg.get("min_refresh_interval_seconds", self.refresh_minutes * 60)
        )
        self.max_results_per_page = int(self.cfg.get("max_results_per_page", 50))
        self.max_items = int(self.cfg.get("max_items", 200))

        self.subscriptions_root_name = str(self.cfg.get("subscriptions_root_name", "Panopto Subscriptions"))
        self.output_root = (self.base_dir / self.cfg.get("output_root_dir", self.cfg.get("feeds_dir", "feeds"))).resolve()
        self.subscriptions_dir = (self.output_root / self.subscriptions_root_name).resolve()

        # All non-feed “data” files go here (keeps project root clean)
        self.data_dir = (self.base_dir / self.cfg.get("data_dir", "data")).resolve()
        self.data_dir.mkdir(parents=True, exist_ok=True)

        # Put index alongside generated outputs (optional, but keeps things tidy)
        self.index_path = (self.output_root / self.cfg.get("index_filename", "index.html")).resolve()

        feeds_json_name = self.cfg.get("feeds_json_filename")
        self.feeds_json_path = (self.data_dir / str(feeds_json_name)).resolve() if feeds_json_name else None

        self.state_path = (self.data_dir / self.cfg.get("state_filename", "state.json")).resolve()
        self.folder_cache_path = (self.data_dir / self.cfg.get("folder_cache_filename", "folder_cache.json")).resolve()
        self.folder_cache_ttl_days = int(self.cfg.get("folder_cache_ttl_days", 7))

        self.token_cache = (self.data_dir / self.cfg.get("token_cache", "panopto_token.json")).resolve()

        # Optional all-in-one feed: disable by removing rss_filename from config
        rss_name = self.cfg.get("rss_filename")
        self.rss_path = (self.output_root / str(rss_name)).resolve() if rss_name else None

        log_path = (self.data_dir / self.cfg.get("log_file", "panopto_rss.log")).resolve()

        self.logger = logging.getLogger("panopto_subscriptions_rss")
        self.logger.setLevel(logging.INFO)
        fh = logging.FileHandler(log_path, encoding="utf-8")
        fh.setFormatter(logging.Formatter("%(asctime)s %(levelname)s %(message)s"))
        self.logger.addHandler(fh)

        self._lock = threading.Lock()
        self._last_refresh_epoch = 0.0

    @property
    def base_url(self) -> str:
        return str(self.cfg.get("base_url") or f"http://127.0.0.1:{self.port}")

    def ensure_fresh(self, force: bool = False) -> None:
        now = time.time()
        if not force and self._last_refresh_epoch and (now - self._last_refresh_epoch) < self.min_refresh_interval_seconds:
            return

        # Do not block concurrent requests during a refresh; serve existing files instead.
        if not self._lock.acquire(blocking=False):
            return

        try:
            now = time.time()
            if not force and self._last_refresh_epoch and (now - self._last_refresh_epoch) < self.min_refresh_interval_seconds:
                return

            self.logger.info("Refreshing RSS...")
            baseline_state = StateStore(self.state_path)
            work_state = StateStore(self.state_path)
            folder_cache = FolderCache(self.folder_cache_path, self.folder_cache_ttl_days, self.logger)

            token = get_access_token(
                server=self.server,
                client_id=self.client_id,
                client_secret=self.client_secret,
                scope=self.scope,
                redirect_uri=self.redirect_uri,
                token_cache=self.token_cache,
                logger=self.logger,
            )

            sessions = fetch_subscriptions_sessions(
                server=self.server,
                access_token=token,
                max_results_per_page=self.max_results_per_page,
                max_items=self.max_items,
                logger=self.logger,
            )

            if self.rss_path is not None:
                build_rss(self.server, sessions, self.rss_path)

            counts = build_folder_feeds_and_index(
                server=self.server,
                sessions=sessions,
                folder_cache=folder_cache,
                state=work_state,
                subscriptions_dir=self.subscriptions_dir,
                subscriptions_root_name=self.subscriptions_root_name,
                base_url=self.base_url,
                index_path=self.index_path,
                feeds_json_path=self.feeds_json_path,
                access_token=token,
                logger=self.logger,
            )

            work_state.last_refresh_utc = _utc_now_iso()
            work_state.last_error = ""
            work_state.last_error_utc = ""
            work_state.last_counts = counts
            work_state.save()
            folder_cache.save_if_dirty()

            self._last_refresh_epoch = time.time()
        except Exception as e:
            # Keep serving existing files. Record error without mutating folder maps.
            self.logger.exception("Refresh error: %s", e)
            baseline_state.last_error = str(e)
            baseline_state.last_error_utc = _utc_now_iso()
            baseline_state.save()
        finally:
            try:
                self._lock.release()
            except Exception:
                pass


def main() -> None:
    config_path = Path(__file__).with_name("config.json")
    app = FeedApp(config_path)

    class Handler(BaseHTTPRequestHandler):
        def do_GET(self) -> None:
            p = urlparse(self.path).path

            def send_text(code: int, text: str, content_type: str) -> None:
                data = text.encode("utf-8")
                self.send_response(code)
                self.send_header("Content-Type", content_type)
                self.send_header("Content-Length", str(len(data)))
                self.end_headers()
                self.wfile.write(data)

            def serve_file(file_path: Path, content_type: str) -> None:
                if not file_path.exists() or not file_path.is_file():
                    send_text(404, "Not found\n", "text/plain; charset=utf-8")
                    return
                data = file_path.read_bytes()
                self.send_response(200)
                self.send_header("Content-Type", content_type)
                self.send_header("Content-Length", str(len(data)))
                self.end_headers()
                self.wfile.write(data)

            if p == "/":
                self.send_response(302)
                self.send_header("Location", "/index.html")
                self.end_headers()
                return

            if p == "/health":
                st = load_json(app.state_path) or {}
                payload = {
                    "last_refresh_utc": st.get("last_refresh_utc"),
                    "last_error": st.get("last_error"),
                    "last_error_utc": st.get("last_error_utc"),
                    "last_counts": st.get("last_counts"),
                }
                send_text(200, json.dumps(payload, indent=2) + "\n", "application/json; charset=utf-8")
                return

            if p == "/refresh":
                # Force an immediate refresh (ignores the 10/15-min TTL)
                app.ensure_fresh(force=True)
                st = load_json(app.state_path) or {}
                payload = {
                    "last_refresh_utc": st.get("last_refresh_utc"),
                    "last_error": st.get("last_error"),
                    "last_error_utc": st.get("last_error_utc"),
                    "last_counts": st.get("last_counts"),
                }
                send_text(
                    200,
                    json.dumps(payload, indent=2) + "\n",
                    "application/json; charset=utf-8",
                )
                return

            if p == "/shutdown":
                send_text(200, "Shutting down\n", "text/plain; charset=utf-8")
                threading.Thread(target=self.server.shutdown, daemon=True).start()
                return

            # Refresh-on-demand (TTL guarded inside ensure_fresh)
            if p in ("/index.html", "/panopto.xml") or p.startswith("/subscriptions/"):
                app.ensure_fresh(force=False)

            if p == "/index.html":
                serve_file(app.index_path, "text/html; charset=utf-8")
                return

            if p == "/panopto.xml":
                if app.rss_path is None:
                    send_text(404, "Not found\n", "text/plain; charset=utf-8")
                else:
                    serve_file(app.rss_path, "application/rss+xml; charset=utf-8")
                return

            if p.startswith("/subscriptions/"):
                rel = unquote(p[len("/subscriptions/"):]).lstrip("/")
                file_path = (app.subscriptions_dir / rel).resolve()
                # Prevent path traversal
                try:
                    sub_root = app.subscriptions_dir.resolve()
                    if file_path != sub_root and sub_root not in file_path.parents:
                        send_text(404, "Not found\n", "text/plain; charset=utf-8")
                        return
                except Exception:
                    send_text(404, "Not found\n", "text/plain; charset=utf-8")
                    return
                ct = "application/rss+xml; charset=utf-8" if file_path.suffix.lower() == ".xml" else "application/octet-stream"
                serve_file(file_path, ct)
                return

            send_text(404, "Not found\n", "text/plain; charset=utf-8")
            return

        def log_message(self, fmt: str, *args) -> None:
            return

    httpd = ThreadingHTTPServer(("127.0.0.1", app.port), Handler)
    app.logger.info("Serving RSS at http://127.0.0.1:%s/index.html", app.port)
    app.ensure_fresh(force=True)  # first build
    httpd.serve_forever()


if __name__ == "__main__":
    main()
