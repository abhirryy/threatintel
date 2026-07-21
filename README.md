# 🛡️ Threat Intel Platform

A self-updating threat intelligence dashboard: **OSINT news**, **threat actors**, and **attack surface** (exploited + newly published CVEs). It refreshes **every 3 hours** and runs **free** on GitHub Pages with your own domain.

See `ARCHITECTURE.md` for the design and roadmap.

---

## What's in here

```
index.html              the dashboard
assets/style.css        styling
assets/app.js           renders data/feed.json into 3 tabs + search
data/feed.json          the data (seeded with sample; auto-refreshed)
sources.yml             your feeds + threat-actor keywords (edit this!)
scripts/fetch_feeds.py  the aggregator
scripts/requirements.txt
.github/workflows/update.yml   runs every 3 hours
CNAME                   your custom domain
```

---

## Deploy it — step by step

You said you'd like some hand-holding, so here's every click. Total time ~15 minutes. You'll need a free [GitHub](https://github.com) account.

### Step 1 — Create the repository
1. Go to https://github.com/new
2. Repository name: `threatintel` (anything is fine).
3. Set it to **Public** (required for free Pages).
4. Do **not** add a README (we already have one). Click **Create repository**.

### Step 2 — Upload these files
Easiest path (no command line):
1. On your new empty repo page, click **uploading an existing file**.
2. Drag in **everything from this folder**, keeping the folder structure (`assets/`, `data/`, `scripts/`, `.github/`).
   - Tip: if drag-and-drop flattens folders, upload folder-by-folder, or use GitHub Desktop.
3. Scroll down, click **Commit changes**.

> Prefer the terminal? From this folder:
> ```
> git init && git add . && git commit -m "initial threat intel platform"
> git branch -M main
> git remote add origin https://github.com/YOUR-USERNAME/threatintel.git
> git push -u origin main
> ```

### Step 3 — Turn on GitHub Pages
1. In the repo, go to **Settings → Pages**.
2. Under **Build and deployment → Source**, choose **Deploy from a branch**.
3. Branch: **main**, folder: **/ (root)**. Click **Save**.
4. Wait ~1 minute. A URL appears like `https://YOUR-USERNAME.github.io/threatintel/`. Open it — you should see the dashboard with the seed data.

### Step 4 — Point `intel.abhishekbh.com.np` at it (via Cloudflare)

Your `.com.np` registrar (register.com.np) only lets you set **nameservers** — it won't accept the DNS record GitHub needs. So we route DNS through **Cloudflare** (free). One-time setup, ~10 min plus propagation.

The repo's `CNAME` file is already set to `intel.abhishekbh.com.np`.

**4a. Add the domain to Cloudflare**
1. Sign up free at https://dash.cloudflare.com → **Add a site** → enter `abhishekbh.com.np` → choose the **Free** plan.
2. Cloudflare scans existing records (fine if none) and shows you **two nameservers**, e.g. `xxx.ns.cloudflare.com` and `yyy.ns.cloudflare.com`. Keep this tab open.

**4b. Set those nameservers at register.com.np**
1. Log in at https://register.com.np → **Domain Registration → My Domain** → select `abhishekbh.com.np`.
2. Find **DNS Configuration / Nameservers** and replace whatever's there with the two Cloudflare nameservers from 4a. Save.
3. `.np` changes can take a few hours (occasionally up to 24–48h). Cloudflare emails you when the domain is **Active**.

**4c. Add the GitHub Pages record in Cloudflare**
Once the domain is Active in Cloudflare, go to **DNS → Records → Add record**:

| Type  | Name    | Target                        | Proxy status        |
|-------|---------|-------------------------------|---------------------|
| CNAME | `intel` | `YOUR-USERNAME.github.io`     | **DNS only** (grey cloud) |

- Replace `YOUR-USERNAME` with your GitHub username (lowercase). No `https://`, no repo name — just `username.github.io`.
- Set Proxy to **DNS only** (click the orange cloud so it turns grey). GitHub needs this to issue the HTTPS certificate. You can turn the proxy on later once HTTPS works.

**4d. Finish in GitHub**
1. In the repo: **Settings → Pages → Custom domain** → enter `intel.abhishekbh.com.np` → **Save**. GitHub runs a DNS check.
2. When the check passes, tick **Enforce HTTPS** (the certificate can take up to an hour to appear).
3. Visit **https://intel.abhishekbh.com.np** — your dashboard is live. 🎉

> Prefer the root `abhishekbh.com.np` instead? Same Cloudflare setup, but add **four A records** on name `@` → `185.199.108.153`, `185.199.109.153`, `185.199.110.153`, `185.199.111.153` (all **DNS only**), and set the `CNAME` file + GitHub custom domain to `abhishekbh.com.np`.

### Step 5 — Confirm the 3-hour auto-update
1. Go to the **Actions** tab. If prompted, click **I understand… enable workflows**.
2. Open **Update threat feed** → **Run workflow** to trigger it once immediately.
3. Watch it run (~1 min). It fetches live feeds and commits an updated `data/feed.json`. Reload your site — real headlines and CVEs replace the sample data.
4. From now on it runs automatically every 3 hours. Nothing else to do.

---

## Customize it

**Add or remove sources** — edit `sources.yml`. For a new news feed, add:
```yaml
  - name: Your Source
    url: https://example.com/feed.xml
```
Commit it; the next run (or a manual **Run workflow**) picks it up.

**Track more threat actors** — add names under `threat_actor_keywords` in `sources.yml`. Any article or CVE mentioning one is tagged and surfaced on the Threat Actors tab.

**Raise the NVD limit (optional)** — get a free key at https://nvd.nist.gov/developers/request-an-api-key, then in the repo go to **Settings → Secrets and variables → Actions → New repository secret**, name it `NVD_API_KEY`, paste the key.

---

## Run it locally (optional)
```bash
pip install -r scripts/requirements.txt
python scripts/fetch_feeds.py      # writes data/feed.json
python -m http.server 8000         # then open http://localhost:8000
```

---

## Troubleshooting

- **Site shows only sample data** → the Action hasn't run yet. Actions tab → Run workflow (Step 5).
- **Action fails on `git push`** → Settings → Actions → General → Workflow permissions → set to **Read and write**.
- **Custom domain "not properly configured"** → DNS still propagating; wait and re-save the domain in Settings → Pages.
- **A feed is empty** → that source may be down or blocking bots; the others still publish. Check the Action log for which one, remove or swap it in `sources.yml`.
```
```
