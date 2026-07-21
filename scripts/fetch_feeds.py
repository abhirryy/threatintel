#!/usr/bin/env python3
"""
Threat Intelligence Platform - feed aggregator.

Pulls OSINT news (RSS), actively-exploited CVEs (CISA KEV) and recent CVEs
(NVD), tags threat-actor mentions, and writes everything to data/feed.json.

Run locally:   python scripts/fetch_feeds.py
In CI:         invoked by .github/workflows/update.yml every 3 hours.

It is intentionally fault-tolerant: if one source is down, the others still
publish. Failures are logged to stderr but never abort the whole run.
"""

import datetime as dt
import html
import json
import os
import re
import sys
import time
from pathlib import Path

import feedparser
import requests
import yaml

ROOT = Path(__file__).resolve().parent.parent
SOURCES_FILE = ROOT / "sources.yml"
OUT_FILE = ROOT / "data" / "feed.json"

UA = "ThreatIntelPlatform/1.0 (+https://github.com) feed-aggregator"
HTTP_TIMEOUT = 25


def log(msg):
    print(f"[fetch] {msg}", file=sys.stderr)


def now_utc():
    return dt.datetime.now(dt.timezone.utc)


def iso(d):
    return d.astimezone(dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def clean_text(raw, limit=320):
    """Strip HTML tags/entities from a summary and truncate."""
    if not raw:
        return ""
    text = re.sub(r"<[^>]+>", " ", raw)
    text = html.unescape(text)
    text = re.sub(r"\s+", " ", text).strip()
    if len(text) > limit:
        text = text[:limit].rsplit(" ", 1)[0] + "…"
    return text


def struct_to_iso(struct_time):
    if not struct_time:
        return None
    try:
        return iso(dt.datetime.fromtimestamp(time.mktime(struct_time), dt.timezone.utc))
    except Exception:
        return None


def match_actors(text, keywords):
    """Return the list of threat-actor keywords found in text (case-insensitive)."""
    found = []
    low = text.lower()
    for kw in keywords:
        # word-ish boundary so 'Play' etc. don't match inside other words
        pattern = r"(?<![a-z0-9])" + re.escape(kw.lower()) + r"(?![a-z0-9])"
        if re.search(pattern, low):
            found.append(kw)
    return sorted(set(found), key=str.lower)


# --------------------------------------------------------------------------- #
#  Sources
# --------------------------------------------------------------------------- #
def fetch_news(feeds, actor_keywords):
    items = []
    for feed in feeds:
        name, url = feed.get("name", "Unknown"), feed.get("url")
        if not url:
            continue
        try:
            parsed = feedparser.parse(url, request_headers={"User-Agent": UA})
            if parsed.bozo and not parsed.entries:
                log(f"news: {name} returned no entries ({parsed.get('bozo_exception')})")
                continue
            for e in parsed.entries[:40]:
                title = clean_text(e.get("title", ""), 240)
                summary = clean_text(e.get("summary", e.get("description", "")))
                link = e.get("link", "")
                published = (
                    struct_to_iso(e.get("published_parsed"))
                    or struct_to_iso(e.get("updated_parsed"))
                    or iso(now_utc())
                )
                actors = match_actors(f"{title} {summary}", actor_keywords)
                items.append(
                    {
                        "title": title,
                        "summary": summary,
                        "url": link,
                        "source": name,
                        "published": published,
                        "actors": actors,
                    }
                )
            log(f"news: {name} -> {len(parsed.entries)} entries")
        except Exception as ex:  # noqa: BLE001
            log(f"news: {name} FAILED: {ex}")
    items.sort(key=lambda x: x["published"], reverse=True)
    return items


def fetch_kev(url, actor_keywords):
    items = []
    try:
        r = requests.get(url, headers={"User-Agent": UA}, timeout=HTTP_TIMEOUT)
        r.raise_for_status()
        data = r.json()
        for v in data.get("vulnerabilities", []):
            title = f"{v.get('cveID','')} - {v.get('vulnerabilityName','')}".strip(" -")
            desc = clean_text(v.get("shortDescription", ""))
            actors = match_actors(f"{title} {desc} {v.get('notes','')}", actor_keywords)
            items.append(
                {
                    "cve": v.get("cveID", ""),
                    "title": title,
                    "summary": desc,
                    "vendor": v.get("vendorProject", ""),
                    "product": v.get("product", ""),
                    "date_added": v.get("dateAdded", ""),
                    "due_date": v.get("dueDate", ""),
                    "ransomware": v.get("knownRansomwareCampaignUse", "Unknown"),
                    "url": f"https://nvd.nist.gov/vuln/detail/{v.get('cveID','')}",
                    "source": "CISA KEV",
                    "published": (v.get("dateAdded", "") + "T00:00:00Z")
                    if v.get("dateAdded")
                    else iso(now_utc()),
                    "actors": actors,
                }
            )
        items.sort(key=lambda x: x["date_added"], reverse=True)
        log(f"kev: {len(items)} exploited CVEs")
    except Exception as ex:  # noqa: BLE001
        log(f"kev: FAILED: {ex}")
    return items


def fetch_nvd(cfg, actor_keywords):
    items = []
    if not cfg.get("enabled", True):
        return items
    lookback = int(cfg.get("lookback_days", 3))
    end = now_utc()
    start = end - dt.timedelta(days=lookback)
    params = {
        "pubStartDate": start.strftime("%Y-%m-%dT%H:%M:%S.000"),
        "pubEndDate": end.strftime("%Y-%m-%dT%H:%M:%S.000"),
        "resultsPerPage": 200,
    }
    headers = {"User-Agent": UA}
    api_key = os.environ.get("NVD_API_KEY")
    if api_key:
        headers["apiKey"] = api_key
    try:
        r = requests.get(
            "https://services.nvd.nist.gov/rest/json/cves/2.0",
            params=params,
            headers=headers,
            timeout=HTTP_TIMEOUT + 15,
        )
        r.raise_for_status()
        data = r.json()
        for entry in data.get("vulnerabilities", []):
            c = entry.get("cve", {})
            cve_id = c.get("id", "")
            descs = c.get("descriptions", [])
            desc = next((d["value"] for d in descs if d.get("lang") == "en"), "")
            # severity
            sev, score = "", None
            metrics = c.get("metrics", {})
            for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
                if metrics.get(key):
                    m = metrics[key][0]["cvssData"]
                    score = m.get("baseScore")
                    sev = m.get("baseSeverity", metrics[key][0].get("baseSeverity", ""))
                    break
            actors = match_actors(f"{cve_id} {desc}", actor_keywords)
            items.append(
                {
                    "cve": cve_id,
                    "title": cve_id,
                    "summary": clean_text(desc, 400),
                    "severity": sev,
                    "cvss": score,
                    "url": f"https://nvd.nist.gov/vuln/detail/{cve_id}",
                    "source": "NVD",
                    "published": c.get("published", iso(now_utc())),
                    "actors": actors,
                }
            )
        # Highest severity first, then newest
        sev_rank = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1, "": 0}
        items.sort(
            key=lambda x: (sev_rank.get((x.get("severity") or "").upper(), 0), x["published"]),
            reverse=True,
        )
        log(f"nvd: {len(items)} recent CVEs")
    except Exception as ex:  # noqa: BLE001
        log(f"nvd: FAILED: {ex}")
    return items


# --------------------------------------------------------------------------- #
#  Main
# --------------------------------------------------------------------------- #
def main():
    cfg = yaml.safe_load(SOURCES_FILE.read_text())
    actor_kw = cfg.get("threat_actor_keywords", [])
    cap = int(cfg.get("max_items_per_section", 60))

    news = fetch_news(cfg.get("news_feeds", []), actor_kw)
    kev = fetch_kev(cfg.get("kev_url", ""), actor_kw)
    nvd = fetch_nvd(cfg.get("nvd", {}), actor_kw)

    # Attack surface = KEV first (exploited), then recent NVD CVEs
    attack_surface = (kev + nvd)[: cap]

    # Threat actors tab = any item (news or vuln) with a matched actor
    actor_items = []
    for it in news:
        if it["actors"]:
            actor_items.append({**it, "kind": "news"})
    for it in kev + nvd:
        if it["actors"]:
            actor_items.append({**it, "kind": "vuln"})
    actor_items.sort(key=lambda x: x.get("published", ""), reverse=True)

    payload = {
        "generated_at": iso(now_utc()),
        "next_update_hint": "every 3 hours",
        "counts": {
            "osint_news": len(news),
            "threat_actors": len(actor_items),
            "attack_surface": len(attack_surface),
        },
        "osint_news": news[:cap],
        "threat_actors": actor_items[:cap],
        "attack_surface": attack_surface,
    }

    OUT_FILE.parent.mkdir(parents=True, exist_ok=True)
    OUT_FILE.write_text(json.dumps(payload, indent=2, ensure_ascii=False))
    log(
        f"wrote {OUT_FILE} : news={len(news)} actors={len(actor_items)} "
        f"attack_surface={len(attack_surface)}"
    )


if __name__ == "__main__":
    main()
