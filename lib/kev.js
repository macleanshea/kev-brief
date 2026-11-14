// Core logic: fetch the CISA KEV feed, cache it, pick out recent entries,
// and render them as HTML. Kept free of Vercel-specific APIs so it can be
// tested with plain `node --test`.

export const FEED_URL =
  process.env.KEV_FEED_URL ||
  'https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json';

export const WINDOW_DAYS = 14;
export const CACHE_TTL_MS = 3 * 60 * 60 * 1000; // 3 hours
const FETCH_TIMEOUT_MS = 10_000;
const DAY_MS = 24 * 60 * 60 * 1000;

/** Format a Date as YYYY-MM-DD in UTC (the same shape as KEV's dateAdded). */
export function isoDate(date) {
  return date.toISOString().slice(0, 10);
}

/**
 * Entries added in the last `days` calendar days (UTC), today included,
 * newest first. With days = 14 on 2026-11-14 that is 2026-11-01..2026-11-14.
 */
export function recentEntries(catalog, { now = new Date(), days = WINDOW_DAYS } = {}) {
  const since = isoDate(new Date(now.getTime() - (days - 1) * DAY_MS));
  const until = isoDate(now);
  const vulns = Array.isArray(catalog?.vulnerabilities) ? catalog.vulnerabilities : [];
  return vulns
    .filter((v) => typeof v.dateAdded === 'string' && v.dateAdded >= since && v.dateAdded <= until)
    .map((v) => ({
      cveID: v.cveID,
      vendor: v.vendorProject,
      product: v.product,
      name: v.vulnerabilityName,
      dateAdded: v.dateAdded,
      ransomware: v.knownRansomwareCampaignUse === 'Known',
    }))
    .sort((a, b) =>
      a.dateAdded === b.dateAdded
        ? b.cveID.localeCompare(a.cveID)
        : a.dateAdded < b.dateAdded ? 1 : -1,
    );
}

/**
 * Returns a function that fetches the catalog, keeping it in memory for
 * `ttlMs`. Serverless instances are reused between requests, so this saves
 * upstream calls when the CDN cache misses. If a refresh fails and an older
 * copy exists, the older copy is served rather than an error.
 */
export function createCatalogLoader({
  fetchImpl = globalThis.fetch,
  url = FEED_URL,
  ttlMs = CACHE_TTL_MS,
  clock = () => Date.now(),
} = {}) {
  let cached = null; // { catalog, fetchedAt }

  return async function loadCatalog() {
    if (cached && clock() - cached.fetchedAt < ttlMs) return { ...cached, stale: false };
    try {
      const res = await fetchImpl(url, {
        headers: { accept: 'application/json' },
        signal: AbortSignal.timeout(FETCH_TIMEOUT_MS),
      });
      if (!res.ok) throw new Error(`KEV feed responded ${res.status}`);
      const catalog = await res.json();
      if (!Array.isArray(catalog?.vulnerabilities)) throw new Error('KEV feed has no vulnerabilities array');
      cached = { catalog, fetchedAt: clock() };
      return { ...cached, stale: false };
    } catch (err) {
      if (cached) return { ...cached, stale: true };
      throw err;
    }
  };
}

const ESCAPES = { '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' };
export function escapeHtml(value) {
  return String(value ?? '').replace(/[&<>"']/g, (c) => ESCAPES[c]);
}

export function renderPage({ entries, catalogVersion, fetchedAt, now = new Date(), days = WINDOW_DAYS }) {
  const rows = entries
    .map(
      (e) => `
        <tr>
          <td data-label="Date added"><time datetime="${escapeHtml(e.dateAdded)}">${escapeHtml(e.dateAdded)}</time></td>
          <td data-label="Vendor">${escapeHtml(e.vendor)}</td>
          <td data-label="Product">${escapeHtml(e.product)}</td>
          <td data-label="CVE"><a href="https://nvd.nist.gov/vuln/detail/${encodeURIComponent(e.cveID)}">${escapeHtml(e.cveID)}</a></td>
          <td data-label="Ransomware">${e.ransomware ? '<span class="tag known">Known</span>' : '<span class="tag unknown">Unknown</span>'}</td>
        </tr>`,
    )
    .join('');

  const body = entries.length
    ? `<table>
        <thead><tr><th>Date added</th><th>Vendor</th><th>Product</th><th>CVE</th><th>Ransomware use</th></tr></thead>
        <tbody>${rows}
        </tbody>
      </table>`
    : `<p class="empty">No vulnerabilities were added to the catalog in the last ${days} days.</p>`;

  return `<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>KEV Brief</title>
  <style>
    :root { color-scheme: light dark; --fg:#1b1f24; --muted:#59636e; --bg:#fff; --line:#d1d9e0; --known-bg:#ffebe9; --known-fg:#a40e26; --unk-bg:#eff2f5; }
    @media (prefers-color-scheme: dark) { :root { --fg:#e6edf3; --muted:#9198a1; --bg:#0d1117; --line:#30363d; --known-bg:#4b1113; --known-fg:#ffa198; --unk-bg:#21262d; } }
    body { margin:0; padding:24px 16px; font:15px/1.5 system-ui, sans-serif; color:var(--fg); background:var(--bg); }
    main { max-width:960px; margin:0 auto; }
    h1 { margin:0 0 4px; font-size:1.6rem; }
    p.meta { margin:0 0 20px; color:var(--muted); }
    table { width:100%; border-collapse:collapse; }
    th, td { text-align:left; padding:8px 10px; border-bottom:1px solid var(--line); vertical-align:top; }
    th { font-size:.8rem; text-transform:uppercase; letter-spacing:.04em; color:var(--muted); }
    td:first-child, td[data-label="CVE"] { white-space:nowrap; font-variant-numeric:tabular-nums; }
    a { color:inherit; }
    .tag { display:inline-block; padding:1px 8px; border-radius:999px; font-size:.8rem; font-weight:600; background:var(--unk-bg); }
    .tag.known { background:var(--known-bg); color:var(--known-fg); }
    @media (max-width:640px) {
      thead { display:none; }
      tr { display:block; padding:10px 0; border-bottom:1px solid var(--line); }
      td { display:flex; gap:12px; border:0; padding:2px 0; }
      td::before { content:attr(data-label); flex:0 0 110px; color:var(--muted); font-size:.85rem; }
    }
  </style>
</head>
<body>
  <main>
    <h1>Known Exploited Vulnerabilities: last ${days} days</h1>
    <p class="meta">${entries.length} ${entries.length === 1 ? 'entry' : 'entries'} added to
      <a href="https://www.cisa.gov/known-exploited-vulnerabilities-catalog">CISA's KEV catalog</a>
      since ${escapeHtml(isoDate(new Date(now.getTime() - (days - 1) * DAY_MS)))}, newest first.
      Catalog version ${escapeHtml(catalogVersion ?? 'unknown')}, fetched ${escapeHtml(new Date(fetchedAt).toISOString())}.</p>
    ${body}
  </main>
</body>
</html>
`;
}
