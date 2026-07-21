// Threat Intel dashboard - loads data/feed.json and renders three tabs.
(function () {
  "use strict";

  const state = { data: null, tab: "osint_news", query: "" };

  const $ = (sel) => document.querySelector(sel);
  const esc = (s) =>
    (s || "").replace(/[&<>"']/g, (c) =>
      ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c])
    );

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

  function card(item) {
    const when = timeAgo(item.published || item.date_added);
    const link = item.url || "#";
    return `
      <article class="card">
        <h3 class="title"><a href="${esc(link)}" target="_blank" rel="noopener">${esc(item.title || item.cve || "Untitled")}</a></h3>
        ${item.summary ? `<p class="summary">${esc(item.summary)}</p>` : ""}
        <div class="row">${chips(item)}${when ? `<span>· ${when}</span>` : ""}</div>
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
    if (!d) return;
    const q = state.query.trim().toLowerCase();

    ["osint_news", "threat_actors", "attack_surface"].forEach((key) => {
      const panel = document.querySelector(`[data-panel="${key}"]`);
      const items = (d[key] || []).filter((it) => matches(it, q));
      $("#c-" + key).textContent = (d[key] || []).length;
      panel.classList.toggle("hidden", key !== state.tab);
      if (key !== state.tab) return;
      panel.innerHTML = items.length
        ? items.map(card).join("")
        : `<div class="empty">No items${q ? " match “" + esc(q) + "”" : " yet"}.</div>`;
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

  load();
  // Re-pull the JSON every 10 minutes so a long-open tab picks up new data.
  setInterval(load, 10 * 60 * 1000);
})();
