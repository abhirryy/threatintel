# Threat Intelligence Platform — Architecture & Roadmap

## 1. Goal

A self-updating threat intelligence dashboard that aggregates:

- **OSINT News** — latest security/breach reporting from trusted outlets
- **Threat Actors** — activity tied to named APTs / criminal groups
- **Attack Surface** — actively exploited and newly published vulnerabilities (CVEs)

It refreshes **every 3 hours**, is hosted **for free** on your own domain, and is built so you can bolt on more sections over time.

## 2. Design principles

- **No server to run or pay for.** The site is 100% static files. A scheduled job rebuilds the data. Nothing runs 24/7, so there is nothing to patch, crash, or get a bill for.
- **Data and presentation are separate.** A script produces one `data/feed.json`; the webpage just reads and renders it. You can change the look without touching the data logic, and vice-versa.
- **Sources are config, not code.** Feeds live in `sources.yml`. Adding a source later = one line, no programming.

## 3. Architecture

```
                 ┌─────────────────────────────────────────┐
                 │   GitHub Actions (cron: every 3 hours)   │
                 │   runs scripts/fetch_feeds.py            │
                 │   • pull RSS news feeds                  │
                 │   • pull CISA KEV (exploited CVEs)       │
                 │   • pull NVD recent CVEs                 │
                 │   • tag threat-actor mentions           │
                 │   → writes data/feed.json, commits it    │
                 └───────────────────┬─────────────────────┘
                                     │ git push
                                     ▼
                 ┌─────────────────────────────────────────┐
                 │   GitHub Pages (free static hosting)     │
                 │   serves index.html + data/feed.json     │
                 │   over HTTPS at your custom domain       │
                 └───────────────────┬─────────────────────┘
                                     │
                                     ▼
                        Visitor's browser renders
                        the dashboard from feed.json
```

**Why GitHub Pages + Actions:** free, includes free HTTPS on a custom domain, the cron scheduler is built in, and the whole thing lives in one repo you own. If you outgrow it (user accounts, a database, search), you migrate the same `fetch_feeds.py` to a small VPS or serverless function — the data contract (`feed.json`) doesn't change.

## 4. Data sources (all free, no API key required to start)

| Section | Source | Type |
|---|---|---|
| OSINT News | The Hacker News, BleepingComputer, Krebs on Security, Dark Reading, The Record, SANS ISC | RSS |
| Attack Surface | CISA Known Exploited Vulnerabilities (KEV) catalog | JSON feed |
| Attack Surface | NVD recent CVEs (last 3 days) | REST API |
| Threat Actors | Derived: news items + KEV entries mentioning known actor names (APTxx, Lazarus, LockBit, etc.) | keyword tagging |

Everything above is public and free. NVD works with no key but is rate-limited; a free key (added later as a GitHub Secret) raises the limit.

## 5. The 3-hour update

A GitHub Actions workflow with `schedule: cron('0 */3 * * *')` runs the aggregator, and commits the refreshed `data/feed.json`. The commit triggers a Pages redeploy automatically. You can also trigger it by hand from the Actions tab (`workflow_dispatch`).

Note: GitHub's cron can lag a few minutes under load — fine for a 3-hour cadence.

## 6. Repository layout

```
threatintel/
├── index.html              # dashboard shell
├── assets/
│   ├── style.css           # styling (dark SOC theme)
│   └── app.js              # loads feed.json, renders tabs, search, filter
├── data/
│   └── feed.json           # generated data (seeded with a sample now)
├── scripts/
│   ├── fetch_feeds.py      # the aggregator
│   └── requirements.txt
├── sources.yml             # editable list of feeds + actor keywords
├── .github/workflows/
│   └── update.yml          # runs every 3 hours
├── CNAME                   # your custom domain
└── README.md               # step-by-step deploy guide
```

## 7. Roadmap (things to add over time)

1. **Filtering/search** — already in the MVP; extend with tag facets.
2. **IOC extraction** — parse IPs, domains, hashes from articles into a structured feed.
3. **MITRE ATT&CK mapping** — link items to techniques/groups using the public ATT&CK STIX data.
4. **Alerting** — a second workflow that emails/Slacks you when a KEV entry or keyword you care about appears.
5. **Historical archive + trends** — keep dated snapshots, chart CVE/actor volume over time.
6. **API** — publish `feed.json` as a documented endpoint others can consume.
7. **Backend upgrade** — when you need accounts, saved searches, or heavy processing, move the aggregator to a VPS/serverless and add a small database. The frontend and data format stay the same.

## 8. Cost

$0/month for hosting and automation. Only cost is your domain registration, which you already own.
