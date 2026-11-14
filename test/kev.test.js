import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';

import { recentEntries, renderPage, createCatalogLoader, escapeHtml, CACHE_TTL_MS } from '../lib/kev.js';
import { createHandler, CACHE_CONTROL } from '../lib/handler.js';

// A real snapshot of the feed (catalog 2026.11.13), trimmed to entries added
// since 2026-07-01. Field names and values are exactly as CISA publishes them.
const sample = JSON.parse(readFileSync(new URL('./fixtures/kev-sample.json', import.meta.url), 'utf8'));
const NOW = new Date('2026-11-14T12:00:00Z');

function jsonResponse(body, status = 200) {
  return new Response(JSON.stringify(body), { status, headers: { 'content-type': 'application/json' } });
}

test('keeps only entries added in the last 14 days, today included', () => {
  const entries = recentEntries(sample, { now: NOW });
  assert.equal(entries.length, 15);
  for (const e of entries) assert.ok(e.dateAdded >= '2026-11-01' && e.dateAdded <= '2026-11-14', e.dateAdded);
  // The day before the window starts is excluded.
  const edge = { vulnerabilities: [
    { ...sample.vulnerabilities[0], cveID: 'CVE-IN', dateAdded: '2026-11-01' },
    { ...sample.vulnerabilities[0], cveID: 'CVE-OUT', dateAdded: '2026-10-31' },
  ] };
  assert.deepEqual(recentEntries(edge, { now: NOW }).map((e) => e.cveID), ['CVE-IN']);
});

test('sorts newest first even when the feed is not sorted', () => {
  const shuffled = { ...sample, vulnerabilities: [...sample.vulnerabilities].reverse() };
  const dates = recentEntries(shuffled, { now: NOW }).map((e) => e.dateAdded);
  assert.deepEqual(dates, [...dates].sort().reverse());
  assert.equal(dates[0], '2026-11-13');
  assert.equal(dates.at(-1), '2026-11-03');
});

test('maps vendor, product, date and ransomware use', () => {
  const [first] = recentEntries(sample, { now: NOW });
  assert.deepEqual(Object.keys(first).sort(), ['cveID', 'dateAdded', 'name', 'product', 'ransomware', 'vendor']);

  // Mid-July 2026 includes two SonicWall entries with known ransomware use.
  const july = recentEntries(sample, { now: new Date('2026-07-20T00:00:00Z') });
  const known = july.filter((e) => e.ransomware);
  assert.deepEqual(known.map((e) => e.cveID).sort(), ['CVE-2026-15409', 'CVE-2026-15410']);
  assert.ok(known.every((e) => e.vendor === 'SonicWall'));
  assert.ok(july.some((e) => !e.ransomware));
});

test('tolerates a catalog without a vulnerabilities array', () => {
  assert.deepEqual(recentEntries({}, { now: NOW }), []);
  assert.deepEqual(recentEntries(null, { now: NOW }), []);
});

test('renders a row per entry with escaped text', () => {
  const entries = recentEntries(sample, { now: NOW });
  const html = renderPage({ entries, catalogVersion: sample.catalogVersion, fetchedAt: NOW.getTime(), now: NOW });
  assert.equal(html.match(/<tr>/g).length, entries.length + 1); // + header row
  assert.match(html, /UnrealIRCd/);
  assert.match(html, /2026\.11\.13/);
  assert.match(html, /15 entries/);

  const evil = renderPage({
    entries: [{ cveID: 'CVE-1', vendor: '<script>x</script>', product: 'A&B', dateAdded: '2026-11-14', ransomware: true }],
    fetchedAt: 0, now: NOW,
  });
  assert.ok(!evil.includes('<script>x'));
  assert.match(evil, /&lt;script&gt;x&lt;\/script&gt;/);
  assert.match(evil, /A&amp;B/);
  assert.match(evil, /class="tag known">Known/);
  assert.equal(escapeHtml(`"'`), '&quot;&#39;');
});

test('renders an empty state when nothing was added', () => {
  const html = renderPage({ entries: [], fetchedAt: 0, now: NOW });
  assert.match(html, /No vulnerabilities were added/);
  assert.ok(!html.includes('<table>'));
});

test('loader caches the feed for the TTL, then refetches', async () => {
  let calls = 0;
  let clock = 0;
  const load = createCatalogLoader({
    fetchImpl: async () => { calls++; return jsonResponse(sample); },
    clock: () => clock,
  });
  await load();
  clock = CACHE_TTL_MS - 1;
  await load();
  assert.equal(calls, 1);
  clock = CACHE_TTL_MS;
  const { catalog, stale } = await load();
  assert.equal(calls, 2);
  assert.equal(stale, false);
  assert.equal(catalog.catalogVersion, '2026.11.13');
});

test('loader serves the stale copy if a refresh fails, and throws if it has none', async () => {
  let clock = 0;
  let fail = false;
  const load = createCatalogLoader({
    fetchImpl: async () => (fail ? jsonResponse({}, 503) : jsonResponse(sample)),
    clock: () => clock,
  });
  await load();
  fail = true;
  clock = CACHE_TTL_MS + 1;
  const result = await load();
  assert.equal(result.stale, true);
  assert.equal(result.catalog.catalogVersion, '2026.11.13');

  const empty = createCatalogLoader({ fetchImpl: async () => jsonResponse({}, 500) });
  await assert.rejects(empty(), /responded 500/);
  const malformed = createCatalogLoader({ fetchImpl: async () => jsonResponse({ nope: true }) });
  await assert.rejects(malformed(), /no vulnerabilities array/);
});

test('handler returns cacheable HTML built from the feed', async () => {
  const handler = createHandler({
    loadCatalog: createCatalogLoader({ fetchImpl: async () => jsonResponse(sample) }),
    now: () => NOW,
  });
  const res = await handler(new Request('https://example.test/'));
  assert.equal(res.status, 200);
  assert.match(res.headers.get('content-type'), /text\/html/);
  assert.equal(res.headers.get('cache-control'), CACHE_CONTROL);
  assert.match(CACHE_CONTROL, /s-maxage=10800/);
  const html = await res.text();
  assert.ok(html.indexOf('CVE-2026-114713') < html.indexOf('CVE-2026-119977'), 'newest first');
});

test('handler returns 502 without caching when the feed is unavailable', async () => {
  const handler = createHandler({ loadCatalog: async () => { throw new Error('down'); } });
  const original = console.error;
  console.error = () => {};
  try {
    const res = await handler(new Request('https://example.test/'));
    assert.equal(res.status, 502);
    assert.equal(res.headers.get('cache-control'), 'no-store');
  } finally {
    console.error = original;
  }
});

test('api/index.js exports a Vercel fetch handler', async () => {
  const { default: fn } = await import('../api/index.js');
  assert.equal(typeof fn.fetch, 'function');
});
