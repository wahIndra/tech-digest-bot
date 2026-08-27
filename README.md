# Daily Tech Digest → Slack & Webhook

A free, self-hosted (as in: hosted on GitHub's dime) bot that posts a daily
8am summary of what's new on your configured topics — CVEs, OWASP-flagged
security news, Java/OpenJDK news, and whatever else you add — to a Slack
channel and/or a custom Webhook endpoint (e.g. your personal website). No server, no paid API, no always-on process.

## How it works

```
GitHub Actions cron (01:00 UTC / 08:00 WIB, daily)
  → digest_bot.py reads config.yaml (your topics)
  → fetches NVD CVE API + RSS feeds + Hacker News (Algolia) per topic
  → drops anything already posted (state/posted.json)
  → filters CVEs by severity threshold, keyword-matches RSS/HN
  → formats a Slack Block Kit message
  → posts via Incoming Webhook
  → commits the updated dedupe log back to the repo
```

Everything here is free: GitHub Actions (2,000 free minutes/month on a
private repo, unlimited on a public one — this job takes under a minute),
the NVD CVE API (public, no key required though a free key raises your
rate limit), RSS feeds, the Hacker News Algolia search API, and Slack
Incoming Webhooks.

## 1. Create the Slack webhook (5 min)

1. Go to <https://api.slack.com/apps> → **Create New App** → **From scratch**.
2. Name it (e.g. "Tech Digest Bot"), pick your workspace.
3. In the left sidebar: **Incoming Webhooks** → toggle **Activate Incoming Webhooks** on.
4. Click **Add New Webhook to Workspace**, choose the channel to post into, **Allow**.
5. Copy the webhook URL. Treat it like a password —
   anyone with this URL can post to that channel.

## 2. Create the GitHub repo

1. Create a new **private** repo (public works too, and gets unlimited Action minutes,
   but a private repo keeps your topic list and webhook usage pattern out of public view).
2. Push everything in this folder to it:
   ```
   git init
   git add .
   git commit -m "Daily tech digest bot"
   git branch -M main
   git remote add origin https://github.com/wahIndra/tech-digest-bot.git
   git push -u origin main
   ```

## 3. Add secrets

Repo → **Settings** → **Secrets and variables** → **Actions** → **New repository secret**:

- `SLACK_WEBHOOK_URL` — the URL from step 1. Required if `WEBSITE_WEBHOOK_URL` is not set.
- `WEBSITE_WEBHOOK_URL` — optional. A URL (e.g., to your personal website's API) to receive the daily digest as a Markdown JSON payload (`{"content": "# Markdown..."}`).
- `WEBSITE_AUTH_TOKEN` — optional. A secret token that will be sent as a Bearer token in the `Authorization` header to your website webhook.
- `NVD_API_KEY` — optional. Get one free at
  <https://nvd.nist.gov/developers/request-an-api-key> (usually issued within minutes).
  Without it you're rate-limited to ~5 requests/30s, which the script already
  paces around with `sleep`s — you only need this if you add a lot of topics/keywords.

## 4. Test it before trusting it

Repo → **Actions** tab → **Daily Tech Digest to Slack** → **Run workflow** (this works
because the workflow has `workflow_dispatch` enabled). Watch the run log; check Slack.
Don't wait for tomorrow's 8am to find out your webhook URL has a typo.

## 5. Configure topics — `config.yaml`

This is the only file you edit to change _what_ the bot watches. Each topic is:

```yaml
- name: "Java"
  keywords: ["Java", "OpenJDK", "JVM"]
  fetchers:
    - type: cve
      min_severity: HIGH # LOW | MEDIUM | HIGH | CRITICAL
    - type: rss
      url: "https://feed.infoq.com/java/"
      filter_by_keywords: false # this feed is already Java-only, don't re-filter
    - type: hn # Hacker News story search on `keywords`
```

Three fetcher types are supported out of the box:

- **`cve`** — searches NVD by keyword, keeps only CVEs at or above `min_severity`.
- **`rss`** — pulls any RSS/Atom feed; set `filter_by_keywords: true` to keep only
  entries whose title/summary match your topic keywords (use this for general feeds
  like a security news aggregator), or `false` for feeds that are already topic-scoped.
- **`hn`** — searches Hacker News (via the Algolia API — no auth, no rate-limit pain)
  for each keyword.

To add a fourth topic, copy a block, rename it, change the keywords. No code changes,
no redeploy — the next scheduled run just picks it up.

## 6. Known limitations (read before you trust this blindly)

- **Reddit is deliberately not used as a source.** Reddit's RSS/API blocks most
  requests coming from cloud/datacenter IPs (which is exactly what GitHub Actions
  runners are), so it fails unpredictably in this setup. Hacker News' Algolia API
  is the "community" source instead — same purpose (catch what people are actually
  discussing), far more automation-friendly. If you specifically need Reddit, you'd
  need Reddit's official OAuth API with registered app credentials — happy to wire
  that up separately if it matters to you.
- **CVE severity filtering only applies to CVEs that already have a CVSS score.**
  Freshly published CVEs sometimes don't have one yet — they're skipped rather than
  shown unscored. This means very-fresh criticals can be missed for a day; the next
  run's `lookback_hours` window (24h) will catch them once NVD scores them, as long
  as they were _published_ within that window.
- **GitHub's cron schedule is "best effort."** GitHub explicitly documents that
  scheduled workflows can be delayed (sometimes 10-30+ min) during high load. If a
  precisely-8:00:00 post matters more than "some time in the 8am hour," this isn't
  the right architecture — you'd want a dedicated scheduler (e.g. a small always-on
  VM or a paid cron service).
- **No LLM summarization.** This posts headlines + links, not AI-condensed summaries,
  specifically to keep the whole thing free. If you want 1-2 line AI summaries per
  item, that's a small addition using the Claude API — but it's a paid API call per
  item, so it wasn't included by default given you asked to keep this free.

## 7. Extending it later

- Want severity escalation (e.g. `@channel` ping only for CRITICAL CVEs)? Add a
  check in `slack_blocks()` for items whose title contains `CRITICAL`.
- Want it in multiple channels by topic? Use a separate webhook per topic and swap
  `post_to_slack` to route per topic name.
- Want AI summaries instead of raw headlines? Swap `item["summary"]` into a call to
  an LLM API in `build_topic_items` before appending — budget for the API cost.
