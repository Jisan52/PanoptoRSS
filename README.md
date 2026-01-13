
# Panopto Subscriptions → Local RSS Feeds

This project runs a small **local** web server that:
- Authenticates to your Panopto tenant via OAuth (first run opens a browser)
- Fetches the same sessions you see in Panopto’s **Subscriptions** page
- Generates:
  - A single combined RSS feed (optional): `panopto.xml`
  - Per-folder RSS feeds: `subscriptions/.../feed.xml`
  - A local index page (`index.html`) to browse/copy feed URLs

The server binds to **127.0.0.1** (localhost) only.

## Files in this repo

- `PanoptoRSS.py` — main server + feed generator
- `config.json` — settings you edit before running
- `requirements.txt` — Python dependencies
- `start_panopto_rss.vbs` — Windows launcher (optional)

---

## Requirements

- Python **3.10+**
- `requests` (see `requirements.txt`)

---

## Setup

### Create a virtual environment (recommended)

From the project folder:

```bash
python -m venv .venv
```

Activate it:
- **Windows**

    ```bash
    .\.venv\Scripts\activate
    ```

- **macOS/Linux**

    ```bash
    source .venv/bin/activate
    ```

Install dependencies:

```bash
pip install -r requirements.txt
```

> The included VBS launcher looks for `.venv\Scripts\pythonw.exe` first, then `venv\Scripts\pythonw.exe`, then falls back to `python` on PATH.

---

## Panopto OAuth setup (you must do this yourself)

You need a Panopto OAuth client (Client ID + Client Secret) from your Panopto tenant/admin UI.

In your `config.json`, set:

- `server` to your tenant base URL, e.g. `https://YOUR_TENANT.cloud.panopto.eu`
- `client_id` / `client_secret` from Panopto
- `redirect_uri` (default is `http://127.0.0.1:8765/callback`)

Make sure the redirect URI you put in `config.json` is also allowed/registered for that OAuth client.

---

## Configuration (`config.json`)

The script reads `config.json` from the same folder as `PanoptoRSS.py`.

Key fields (matching the shipped template) :

- `server`: Panopto tenant URL (no trailing slash recommended)
- `client_id`: OAuth client id
- `client_secret`: OAuth client secret
- `scope`: usually `"api"`
- `redirect_uri`: localhost callback used during OAuth login
- `port`: local server port for the RSS/index server (default 8080)
- `refresh_minutes`: refresh cadence used to derive defaults
- `min_refresh_interval_seconds`: minimum time between refreshes when refresh is triggered by viewing feeds/index
- `max_results_per_page`, `max_items`: paging/limit controls for subscription fetch
- `subscriptions_root_name`: folder label used in generated tree
- `output_root_dir`: where generated `index.html`, `panopto.xml`, and per-folder feeds are written
- `data_dir`: where token/log/cache/state are stored
- `token_cache`, `log_file`, `state_filename`, `folder_cache_filename`, `folder_cache_ttl_days`, `index_filename`
- `rss_filename`: name of the combined feed file. If you remove `rss_filename` from the config, the combined feed is disabled.

---

## Running

### Option A: run with Python

```bash
python PanoptoRSS.py
```

Then open:

- `http://127.0.0.1:PORT/index.html` (PORT is `config.json` → `port`)

First run will open a browser window for Panopto login and authorization, then it caches tokens locally under `data_dir`.

### Option B (Windows): run with the VBS launcher

Double-click:

- `start_panopto_rss.vbs`

What the VBS does:

- If the server is already running: calls `http://127.0.0.1:PORT/refresh`, then opens `/index.html`
- If not running: starts the server, waits until `/health` responds, calls `/refresh`, then opens `/index.html`

---

## Creating a Shortcut for the VBS (Windows)

1. Right-click `start_panopto_rss.vbs`
2. Click **Create shortcut**
3. Move the shortcut wherever you want (Desktop, Start Menu, etc.)

Important:

- Keep the **actual** `.vbs` file inside the project folder.
- The shortcut can live anywhere; it will still launch the VBS from the project folder.

Optional: auto-start on login

- Put the shortcut into:  
    `%APPDATA%\Microsoft\Windows\Start Menu\Programs\Startup`

### Windows VBS launcher: environment expectations

The VBS launcher tries (in order):

1) `.venv\Scripts\pythonw.exe`
2) `venv\Scripts\pythonw.exe`
3) `python` from your PATH

So:
- If you create a venv named `.venv` in the project folder, the VBS will “just work”.
- If your environment folder has a different name/location, either rename it to `.venv`/`venv`, or skip the VBS and run `python PanoptoRSS.py` manually.

Why `pythonw.exe`?
- It runs without opening a console window.
- If something fails, check `data_dir/panopto_rss.log` and `/health` for the last error.

---

## Using the RSS feeds

### Generated files & directory layout

On first run, the script creates two folders (relative to the project folder):

- `output_root_dir` (default: `feeds/`)
	- `index.html` (the local UI)
	- `panopto.xml` (combined feed, only if `rss_filename` is set)
	- `subscriptions_root_name/` (default: `Panopto Subscriptions/`)
		- A nested folder tree that mirrors your Panopto folder hierarchy
		- Each *leaf* folder contains a `feed.xml`

- `data_dir` (default: `data/`)
	- `panopto_token.json` (OAuth token cache)
	- `state.json` (last refresh time + folder signatures/paths)
	- `folder_cache.json` (folder name/parent cache; TTL controlled by `folder_cache_ttl_days`)
	- `panopto_rss.log` (logs + errors)

Notes:
- Folder/file names are made Windows-safe (invalid characters replaced, trailing dots/spaces removed).
- If Panopto folder names collide after sanitizing, the script may suffix names like `_2`, `_3`, etc.
- When a folder disappears from your Subscriptions results, its generated feed folder can be deleted automatically on refresh.

### Index page

Open:

- `http://127.0.0.1:PORT/index.html`

It shows your subscription folder tree and provides “Open feed” / “Copy URL” buttons.

### Feed URLs you can subscribe to

- Combined feed (if enabled):  
    `http://127.0.0.1:PORT/panopto.xml`
- Per-folder feeds: served under:  
    `http://127.0.0.1:PORT/subscriptions/.../feed.xml`

Any RSS reader should work. (The feeds are local; they update when this server is running and refreshing.)

### Refresh behaviour

- Visiting `/index.html`, `/panopto.xml`, or anything under `/subscriptions/` triggers a refresh only if enough time has passed (`min_refresh_interval_seconds`).
- Calling `/refresh` - i.e. “Refresh now” (button on the index page) - forces an immediate refresh regardless of the interval.
- The VBS launcher always calls `/refresh` after launch (and also if already running).

### Shutdown/stop behavior

There are two ways to stop the local server:

- From the index page: click **Stop server** (calls `/shutdown`).
	- This triggers a graceful shutdown of the local HTTP server process.
	- It does **not** delete any generated files; `feeds/` and `data/` stay on disk.
- If you started it in a terminal (Option A): press **Ctrl+C** in that terminal window.

To start again, run `python PanoptoRSS.py` or double-click `start_panopto_rss.vbs`.

The `/shutdown` endpoint returns “Shutting down” and then calls the server’s shutdown method in a background thread.

---

## Troubleshooting

- If login breaks or tokens are stale: stop the server, delete the token cache file in `data_dir` (default: `data/panopto_token.json`), then rerun.
- If feeds aren’t reachable: check that `port` in `config.json` matches the URL you’re using.
- If you see 404s for subscription feeds: make sure you actually have items in your Panopto Subscriptions page.
