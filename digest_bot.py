#!/usr/bin/env python3
"""
Daily Tech Digest -> Slack

Reads config.yaml for topic/keyword/source definitions, fetches new items
from the last `lookback_hours`, dedupes against state/posted.json, formats
a Slack Block Kit message, and posts it via an Incoming Webhook.

Env vars:
  SLACK_WEBHOOK_URL   required  -- Slack incoming webhook URL
  NVD_API_KEY         optional  -- raises NVD's rate limit (unauth: ~5 req/30s)

Exit codes: non-zero on hard failures (bad webhook, bad config) so the
GitHub Actions run shows red and you actually notice.
"""
import os
import sys
import json
import time
import yaml
import feedparser
import requests
from datetime import datetime, timedelta, timezone

STATE_PATH = "state/posted.json"
NVD_ENDPOINT = "https://services.nvd.nist.gov/rest/json/cves/2.0"
HN_ENDPOINT = "https://hn.algolia.com/api/v1/search_by_date"
SEVERITY_ORDER = {"LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}


# ── state (dedupe log) ────────────────────────────────────────────────────

def load_state():
    if os.path.exists(STATE_PATH):
        with open(STATE_PATH) as f:
            return json.load(f)
    return {"seen": {}}


def save_state(state, keep_days=14):
    cutoff = (datetime.now(timezone.utc) - timedelta(days=keep_days)).isoformat()
    state["seen"] = {k: v for k, v in state["seen"].items() if v >= cutoff}
    os.makedirs(os.path.dirname(STATE_PATH), exist_ok=True)
    with open(STATE_PATH, "w") as f:
        json.dump(state, f, indent=2, sort_keys=True)


# ── fetchers ───────────────────────────────────────────────────────────────

def fetch_cve(keywords, min_severity, since, api_key=None):
    """NVD CVE API 2.0. Fetches by keyword, then filters client-side for
    'at or above' min_severity, since the API only accepts one exact
    severity value per call."""
    headers = {"apiKey": api_key} if api_key else {}
    items = []
    threshold = SEVERITY_ORDER.get(min_severity, 3)
    for kw in keywords:
        params = {
            "keywordSearch": kw,
            "pubStartDate": since.strftime("%Y-%m-%dT%H:%M:%S.000"),
            "pubEndDate": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.000"),
            "resultsPerPage": 50,
        }
        try:
            r = requests.get(NVD_ENDPOINT, params=params, headers=headers, timeout=30)
            r.raise_for_status()
        except requests.RequestException as e:
            print(f"  [cve] request failed for '{kw}': {e}", file=sys.stderr)
            time.sleep(6)
            continue
        for v in r.json().get("vulnerabilities", []):
            cve = v.get("cve", {})
            severity, score = _cve_severity(cve)
            if severity is None or SEVERITY_ORDER.get(severity, 0) < threshold:
                continue
            desc = next(
                (d["value"] for d in cve.get("descriptions", []) if d.get("lang") == "en"),
                "",
            )
            items.append({
                "id": cve["id"],
                "title": f"{cve['id']} ({severity}{f', {score}' if score else ''})",
                "summary": desc[:200],
                "url": f"https://nvd.nist.gov/vuln/detail/{cve['id']}",
                "source": "NVD",
            })
        time.sleep(6)  # be polite to the unauthenticated rate limit
    return items


def _cve_severity(cve):
    metrics = cve.get("metrics", {})
    for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
        entries = metrics.get(key)
        if entries:
            data = entries[0]["cvssData"]
            severity = data.get("baseSeverity") or entries[0].get("baseSeverity")
            return (severity, data.get("baseScore"))
    return (None, None)


def fetch_rss(url, keywords, filter_by_keywords, since):
    items = []
    feed = feedparser.parse(url)
    for entry in feed.entries:
        published = _entry_time(entry)
        if published and published < since:
            continue
        title = entry.get("title", "")
        summary = entry.get("summary", "")
        if filter_by_keywords and not _matches_any(f"{title} {summary}", keywords):
            continue
        items.append({
            "id": entry.get("link", title),
            "title": title,
            "summary": summary[:200],
            "url": entry.get("link", ""),
            "source": feed.feed.get("title", url),
        })
    return items


def _entry_time(entry):
    for field in ("published_parsed", "updated_parsed"):
        t = entry.get(field)
        if t:
            return datetime(*t[:6], tzinfo=timezone.utc)
    return None


def fetch_hn(keywords, since):
    items = []
    since_ts = int(since.timestamp())
    for kw in keywords:
        params = {"query": kw, "tags": "story", "numericFilters": f"created_at_i>{since_ts}"}
        try:
            r = requests.get(HN_ENDPOINT, params=params, timeout=20)
            r.raise_for_status()
        except requests.RequestException as e:
            print(f"  [hn] request failed for '{kw}': {e}", file=sys.stderr)
            continue
        for hit in r.json().get("hits", []):
            items.append({
                "id": hit.get("objectID"),
                "title": hit.get("title") or "(untitled)",
                "summary": "",
                "url": hit.get("url") or f"https://news.ycombinator.com/item?id={hit.get('objectID')}",
                "source": "Hacker News",
            })
    return items


def _matches_any(text, keywords):
    text = text.lower()
    return any(kw.lower() in text for kw in keywords)


# ── digest assembly ─────────────────────────────────────────────────────

def build_topic_items(topic, since, state, nvd_api_key):
    seen = state["seen"]
    raw = []
    for fetcher in topic.get("fetchers", []):
        ftype = fetcher["type"]
        if ftype == "cve":
            raw += fetch_cve(topic["keywords"], fetcher.get("min_severity", "HIGH"), since, nvd_api_key)
        elif ftype == "rss":
            raw += fetch_rss(
                fetcher["url"], topic["keywords"], fetcher.get("filter_by_keywords", True), since
            )
        elif ftype == "hn":
            raw += fetch_hn(topic["keywords"], since)
        else:
            print(f"  [warn] unknown fetcher type '{ftype}' in topic '{topic['name']}'", file=sys.stderr)

    new_items, dupe_ids = [], set()
    for item in raw:
        iid = item["id"]
        if iid in seen or iid in dupe_ids:
            continue
        dupe_ids.add(iid)
        new_items.append(item)
    return new_items


def slack_blocks(date_str, topics_with_items, max_items_per_topic, post_if_empty):
    blocks = [
        {"type": "header", "text": {"type": "plain_text", "text": f"🗞️ Daily Tech Digest — {date_str}"}},
    ]
    any_content = False
    for topic_name, items in topics_with_items:
        if not items and not post_if_empty:
            continue
        any_content = True
        blocks.append({"type": "divider"})
        blocks.append({"type": "section", "text": {"type": "mrkdwn", "text": f"*{topic_name}*"}})
        if not items:
            blocks.append({"type": "section", "text": {"type": "mrkdwn", "text": "_No new items today._"}})
            continue
        shown = items[:max_items_per_topic]
        lines = [f"• <{i['url']}|{i['title']}>  _({i['source']})_" for i in shown]
        if len(items) > max_items_per_topic:
            lines.append(f"_+{len(items) - max_items_per_topic} more_")
        blocks.append({"type": "section", "text": {"type": "mrkdwn", "text": "\n".join(lines)}})
    if not any_content:
        blocks.append({"type": "section", "text": {"type": "mrkdwn", "text": "No new items across any topic today."}})
    return blocks


def post_to_slack(webhook_url, blocks):
    r = requests.post(webhook_url, json={"blocks": blocks}, timeout=20)
    if r.status_code != 200:
        raise RuntimeError(f"Slack webhook returned {r.status_code}: {r.text}")


# ── main ───────────────────────────────────────────────────────────────

def main():
    webhook_url = os.environ.get("SLACK_WEBHOOK_URL")
    if not webhook_url:
        print("SLACK_WEBHOOK_URL is not set.", file=sys.stderr)
        sys.exit(1)
    nvd_api_key = os.environ.get("NVD_API_KEY")  # optional

    with open("config.yaml") as f:
        config = yaml.safe_load(f)

    since = datetime.now(timezone.utc) - timedelta(hours=config.get("lookback_hours", 24))
    state = load_state()

    results = []
    for topic in config["topics"]:
        print(f"Fetching topic: {topic['name']}")
        items = build_topic_items(topic, since, state, nvd_api_key)
        results.append((topic["name"], items))
        today = datetime.now(timezone.utc).date().isoformat()
        for item in items:
            state["seen"][item["id"]] = today

    date_str = datetime.now(timezone.utc).astimezone(
        timezone(timedelta(hours=7))  # Asia/Jakarta, no external tz db dependency
    ).strftime("%Y-%m-%d")

    blocks = slack_blocks(
        date_str, results, config.get("max_items_per_topic", 8), config.get("post_if_empty", True)
    )
    post_to_slack(webhook_url, blocks)
    save_state(state)
    print("Done.")


if __name__ == "__main__":
    main()
