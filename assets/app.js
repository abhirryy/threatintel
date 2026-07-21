// Threat Intel dashboard - loads data/feed.json and renders three tabs.
(function () {
  "use strict";

  const state = { data: null, tab: "osint_news", query: "", rendered: {}, openItem: null };

  const $ = (sel) => document.querySelector(sel);
  const esc = (s) =>
    (s || "").replace(/[&<>"']/g, (c) =>
      ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c])
    );

  // -------------------------------------------------------------------- //
  //  Theme toggle (persisted in localStorage)
  // -------------------------------------------------------------------- //
  const THEME_KEY = "ti-theme";

  function applyTheme(theme) {
    document.documentElement.setAttribute("data-theme", theme);
    const icon = document.getElementById("theme-icon");
    if (icon) icon.textContent = theme === "light" ? "🌙" : "☀️";
  }

  function initTheme() {
    const saved = localStorage.getItem(THEME_KEY) || "dark";
    applyTheme(saved);
  }

  function toggleTheme() {
    const current = document.documentElement.getAttribute("data-theme") || "dark";
    const next = current === "light" ? "dark" : "light";
    localStorage.setItem(THEME_KEY, next);
    applyTheme(next);
  }

  // -------------------------------------------------------------------- //
  //  Bookmarks (client-side only, stored in this browser's localStorage)
  // -------------------------------------------------------------------- //
  const BOOKMARK_KEY = "ti-bookmarks";

  function loadBookmarks() {
    try {
      return JSON.parse(localStorage.getItem(BOOKMARK_KEY)) || {};
    } catch (e) {
      return {};
    }
  }

  function saveBookmarks(map) {
    localStorage.setItem(BOOKMARK_KEY, JSON.stringify(map));
  }

  function bookmarkId(item) {
    return item.url || item.cve || item.title || "";
  }

  function isBookmarked(id) {
    return !!loadBookmarks()[id];
  }

  function bookmarkCount() {
    return Object.keys(loadBookmarks()).length;
  }

  // Toggles the bookmark and returns the new state (true = now saved).
  function toggleBookmark(item) {
    const id = bookmarkId(item);
    if (!id) return false;
    const map = loadBookmarks();
    if (map[id]) {
      delete map[id];
      saveBookmarks(map);
      return false;
    }
    map[id] = { ...item, _savedAt: new Date().toISOString() };
    saveBookmarks(map);
    return true;
  }

  function bookmarkedItems() {
    return Object.values(loadBookmarks()).sort((a, b) =>
      (b._savedAt || "").localeCompare(a._savedAt || "")
    );
  }

  // -------------------------------------------------------------------- //
  //  IOC extraction (client-side, heuristic — pulled from title/summary)
  // -------------------------------------------------------------------- //
  const IOC_PATTERNS = [
    { kind: "CVE", re: /\bCVE-\d{4}-\d{4,7}\b/gi },
    { kind: "SHA256", re: /\b[a-f0-9]{64}\b/gi },
    { kind: "SHA1", re: /\b[a-f0-9]{40}\b/gi },
    { kind: "MD5", re: /\b[a-f0-9]{32}\b/gi },
    { kind: "IPv4", re: /\b(?:\d{1,3}\.){3}\d{1,3}\b/g },
    {
      kind: "Domain",
      re: /\b(?:[a-z0-9-]{1,63}\.)+(?:com|net|org|io|ru|cn|info|biz|xyz|top|club|online|site|shop|link|click|gov|edu|co|uk|de|app|dev|cloud|live|pw|icu|me|tv|cc)\b/gi,
    },
  ];

  function extractIocs(item) {
    const text = [item.title, item.summary].filter(Boolean).join(" ");
    const found = [];
    const seen = new Set();

    if (item.cve) {
      found.push({ kind: "CVE", value: item.cve });
      seen.add("CVE:" + item.cve.toLowerCase());
    }

    for (const { kind, re } of IOC_PATTERNS) {
      const matches = text.match(re) || [];
      for (const m of matches) {
        const key = kind + ":" + m.toLowerCase();
        if (seen.has(key)) continue;
        seen.add(key);
        found.push({ kind, value: m });
      }
    }

    if (item.vendor) {
      found.push({ kind: "Vendor", value: item.vendor + (item.product ? " / " + item.product : "") });
    }
    return found;
  }

  // -------------------------------------------------------------------- //
  //  Plan of action (templated from item metadata — no external calls)
  // -------------------------------------------------------------------- //
  function buildPlan(item) {
    const plan = [];
    const isVuln = !!item.cve;
    const exploited = item.source === "CISA KEV" || (item.ransomware && item.ransomware.toLowerCase() === "known");

    if (isVuln) {
      plan.push(
        `Check whether ${esc(item.vendor || "the affected vendor")}${item.product ? " " + esc(item.product) : ""} is deployed in your environment and confirm the patch level against ${esc(item.cve)}.`
      );
      plan.push("Apply the vendor patch or documented mitigation as soon as change control allows.");
      if (exploited) {
        plan.push("This CVE is actively exploited — prioritize it above routine patch-cycle timelines.");
      }
      if (item.due_date) {
        plan.push(`CISA KEV remediation due date: ${esc(item.due_date)}.`);
      }
    }

    if ((item.actors || []).length) {
      const actors = item.actors.join(", ");
      plan.push(`Search EDR/SIEM telemetry for TTPs associated with ${esc(actors)}.`);
      plan.push(`Review current detection rules against ${esc(actors)}'s known infrastructure and update as needed.`);
    }

    if (!isVuln && !(item.actors || []).length) {
      plan.push("Read the full article to assess relevance to your organization's assets and vendors.");
      plan.push("Watch for follow-up reporting or an official IOC/advisory release from the source.");
    }

    plan.push("Cross-reference any indicators above against your SIEM, firewall, and EDR logs.");
    plan.push("Share with your SOC/IR team if it touches systems or vendors you operate.");

    return plan;
  }

  // -------------------------------------------------------------------- //
  //  Detail modal
  // -------------------------------------------------------------------- //
  function setBookmarkBtn(btn, saved) {
    btn.textContent = saved ? "★ Saved" : "☆ Save";
    btn.setAttribute("aria-pressed", saved ? "true" : "false");
  }

  function openDetail(item) {
    state.openItem = item;
    $("#detail-title").textContent = item.title || item.cve || "Untitled";
    $("#detail-meta").innerHTML = chips(item) + (item.published || item.date_added
      ? `<span>· ${esc(timeAgo(item.published || item.date_added))}</span>`
      : "");
    const link = $("#detail-link");
    if (item.url) {
      link.href = item.url;
      link.style.display = "inline-block";
    } else {
      link.style.display = "none";
    }
    $("#detail-summary").textContent = item.summary || "No summary available for this item.";

    const iocs = extractIocs(item);
    $("#detail-iocs").innerHTML = iocs.length
      ? `<div class="ioc-list">${iocs
          .map((i) => `<span class="ioc-chip"><span class="ioc-kind">${esc(i.kind)}</span>${esc(i.value)}</span>`)
          .join("")}</div>`
      : `<div class="ioc-empty">No structured indicators detected in this report — check the full article for IOCs.</div>`;

    const plan = buildPlan(item);
    $("#detail-plan").innerHTML = plan.map((p) => `<li>${p}</li>`).join("");

    setBookmarkBtn($("#detail-bookmark"), isBookmarked(bookmarkId(item)));

    $("#detail-overlay").classList.remove("hidden");
  }

  function closeDetail() {
    $("#detail-overlay").classList.add("hidden");
    state.openItem = null;
  }

  function timeAgo(iso) {
    if (!iso) return "";
    const d = new Date(iso);
    if (isNaN(d)) return "";
    const s = Math.floor((Date.now() - d.getTime()) / 1000);
    if (s < 60) return "just now";
    const m = Math.floor(s / 60);
    if (m < 60) return m + "m ago";
    const h = Math.floor(m / 60);
    if (h < 24) return h + "h ago";
    const dd = Math.floor(h / 24);
    return dd + "d ago";
  }

  function chips(item) {
    const out = [];
    if (item.source) out.push(`<span class="chip source">${esc(item.source)}</span>`);
    if (item.severity)
      out.push(`<span class="sev ${esc(item.severity.toUpperCase())}">${esc(item.severity)}${item.cvss ? " " + item.cvss : ""}</span>`);
    (item.actors || []).forEach((a) => out.push(`<span class="chip actor">${esc(a)}</span>`));
    if (item.ransomware && item.ransomware.toLowerCase() === "known")
      out.push(`<span class="chip ransom">ransomware</span>`);
    if (item.vendor) out.push(`<span class="chip">${esc(item.vendor)}${item.product ? " · " + esc(item.product) : ""}</span>`);
    return out.join(" ");
  }

  function card(item, tab, idx) {
    const when = timeAgo(item.published || item.date_added);
    const link = item.url || "#";
    const saved = isBookmarked(bookmarkId(item));
    return `
      <article class="card" data-tab="${esc(tab)}" data-idx="${idx}">
        <h3 class="title"><a href="${esc(link)}" target="_blank" rel="noopener">${esc(item.title || item.cve || "Untitled")}</a></h3>
        ${item.summary ? `<p class="summary">${esc(item.summary)}</p>` : ""}
        <div class="row">${chips(item)}${when ? `<span>· ${when}</span>` : ""}<span class="details-link">View details →</span><button class="bookmark-btn" data-action="bookmark" aria-pressed="${saved}">${saved ? "★ Saved" : "☆ Save"}</button></div>
      </article>`;
  }

  function matches(item, q) {
    if (!q) return true;
    const hay = [item.title, item.summary, item.source, item.cve, (item.actors || []).join(" "), item.vendor, item.product]
      .join(" ")
      .toLowerCase();
    return hay.includes(q);
  }

  function render() {
    const d = state.data;
    const q = state.query.trim().toLowerCase();

    ["osint_news", "threat_actors", "attack_surface", "bookmarks"].forEach((key) => {
      const isBookmarksTab = key === "bookmarks";
      if (!isBookmarksTab && !d) return; // feed not loaded yet; nothing to show
      const panel = document.querySelector(`[data-panel="${key}"]`);
      const all = isBookmarksTab ? bookmarkedItems() : d[key] || [];
      const items = all.filter((it) => matches(it, q));
      $("#c-" + key).textContent = key === "bookmarks" ? bookmarkCount() : all.length;
      panel.classList.toggle("hidden", key !== state.tab);
      if (key !== state.tab) return;
      state.rendered[key] = items;
      const emptyMsg =
        key === "bookmarks" && !q
          ? "No saved items yet — click “Save” on any item to bookmark it for later."
          : `No items${q ? " match “" + esc(q) + "”" : " yet"}.`;
      panel.innerHTML = items.length
        ? items.map((it, i) => card(it, key, i)).join("")
        : `<div class="empty">${emptyMsg}</div>`;
    });
  }

  function setTab(tab) {
    state.tab = tab;
    document.querySelectorAll(".tab").forEach((b) =>
      b.classList.toggle("active", b.dataset.tab === tab)
    );
    render();
  }

  async function load() {
    try {
      const res = await fetch("data/feed.json?_=" + Date.now());
      if (!res.ok) throw new Error("HTTP " + res.status);
      state.data = await res.json();
      $("#loader").style.display = "none";
      const stamp = state.data.generated_at
        ? "Updated " + timeAgo(state.data.generated_at)
        : "";
      $("#updated").textContent = stamp;
      $("#foot-updated").textContent = state.data.generated_at
        ? new Date(state.data.generated_at).toLocaleString()
        : "";
      render();
    } catch (e) {
      $("#loader").textContent = "Could not load feed.json (" + e.message + ").";
    }
  }

  document.getElementById("tabs").addEventListener("click", (e) => {
    const btn = e.target.closest(".tab");
    if (btn) setTab(btn.dataset.tab);
  });
  document.getElementById("search").addEventListener("input", (e) => {
    state.query = e.target.value;
    render();
  });

  document.getElementById("content").addEventListener("click", (e) => {
    if (e.target.closest("a")) return; // let the outbound article link work normally
    const cardEl = e.target.closest(".card");
    if (!cardEl) return;
    const tab = cardEl.dataset.tab;
    const idx = Number(cardEl.dataset.idx);
    const item = (state.rendered[tab] || [])[idx];
    if (!item) return;

    if (e.target.closest('[data-action="bookmark"]')) {
      toggleBookmark(item);
      render();
      return;
    }
    openDetail(item);
  });

  document.getElementById("theme-toggle").addEventListener("click", toggleTheme);
  document.getElementById("detail-close").addEventListener("click", closeDetail);
  document.getElementById("detail-overlay").addEventListener("click", (e) => {
    if (e.target.id === "detail-overlay") closeDetail();
  });
  document.addEventListener("keydown", (e) => {
    if (e.key === "Escape") closeDetail();
  });
  document.getElementById("detail-bookmark").addEventListener("click", () => {
    if (!state.openItem) return;
    const saved = toggleBookmark(state.openItem);
    setBookmarkBtn($("#detail-bookmark"), saved);
    render(); // keep tab counts / underlying card / bookmarks list in sync
  });

  // -------------------------------------------------------------------- //
  //  Live polling: the open tab re-checks feed.json every 2 minutes.
  //  A manual refresh (button) fetches immediately and restarts the timer,
  //  so it never waits out whatever time is left on the automatic cycle.
  // -------------------------------------------------------------------- //
  const POLL_MS = 2 * 60 * 1000;
  let pollTimer = null;

  function schedulePoll() {
    if (pollTimer) clearInterval(pollTimer);
    pollTimer = setInterval(load, POLL_MS);
  }

  document.getElementById("refresh-btn").addEventListener("click", async () => {
    const btn = document.getElementById("refresh-btn");
    btn.classList.add("spin");
    await load();
    btn.classList.remove("spin");
    schedulePoll();
  });

  initTheme();
  load();
  schedulePoll();
})();
