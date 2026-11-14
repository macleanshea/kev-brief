import { createCatalogLoader, recentEntries, renderPage, inWindow, CACHE_TTL_MS, WINDOW_DAYS } from './kev.js';
import { createExplainer, findEntry, CVE_PATTERN } from './explain.js';
import { blobConfigured, createBlobStore, createMemoryStore } from './store.js';

// Vercel's CDN keeps the rendered page for the cache TTL and may serve it
// stale for another hour while it regenerates in the background.
export const CACHE_CONTROL = `public, max-age=0, s-maxage=${CACHE_TTL_MS / 1000}, stale-while-revalidate=3600`;

/** Build a Web-standard request handler (Request -> Response). */
export function createHandler({ loadCatalog = createCatalogLoader(), now = () => new Date() } = {}) {
  return async function handler() {
    try {
      const { catalog, fetchedAt, stale } = await loadCatalog();
      const current = now();
      const html = renderPage({
        entries: recentEntries(catalog, { now: current }),
        catalogVersion: catalog.catalogVersion,
        fetchedAt,
        now: current,
      });
      return new Response(html, {
        status: 200,
        headers: {
          'content-type': 'text/html; charset=utf-8',
          // Don't let the CDN hold a fallback copy for hours.
          'cache-control': stale ? 'public, max-age=0, s-maxage=300' : CACHE_CONTROL,
        },
      });
    } catch (err) {
      console.error('Failed to load KEV feed:', err);
      return new Response('The CISA KEV feed could not be loaded. Please try again shortly.', {
        status: 502,
        headers: { 'content-type': 'text/plain; charset=utf-8', 'cache-control': 'no-store' },
      });
    }
  };
}

// Explanations don't change for a CVE, so the CDN can keep them for a week.
export const EXPLAIN_CACHE_CONTROL = 'public, max-age=0, s-maxage=604800, stale-while-revalidate=86400';

function json(body, status, cacheControl = 'no-store') {
  return new Response(JSON.stringify(body), {
    status,
    headers: { 'content-type': 'application/json; charset=utf-8', 'cache-control': cacheControl },
  });
}

// Redirects to the standard URL never change, so the CDN can keep them too.
const REDIRECT_CACHE_CONTROL = 'public, max-age=86400, s-maxage=604800';

/**
 * Explanations are on when there is an API key and somewhere lasting to keep
 * the answers. On Vercel that must be a Blob store, or every new instance
 * would pay for the same CVEs again; local runs may use memory.
 */
export function explainConfigured(env = process.env) {
  return Boolean(env.ANTHROPIC_API_KEY) && (blobConfigured(env) || !env.VERCEL);
}

/** Lazily builds the Claude-backed explainer, so the SDKs only load when used. */
function defaultExplain() {
  let explain;
  return async (entry) => {
    if (!explain) {
      const { default: Anthropic } = await import('@anthropic-ai/sdk');
      const store = blobConfigured() ? createBlobStore({ blob: await import('@vercel/blob') }) : createMemoryStore();
      explain = createExplainer({ client: new Anthropic(), store });
    }
    return explain(entry);
  };
}

// Explain accepts one day more than the page shows: the CDN can serve a page
// rendered the day before, and its buttons should still work.
export const EXPLAIN_WINDOW_DAYS = WINDOW_DAYS + 1;

/**
 * GET /api/explain?cve=CVE-YYYY-NNNN -> { cveID, sentences: [product, attacker, audience] }.
 * Only CVEs added to the KEV catalog within EXPLAIN_WINDOW_DAYS are explained,
 * which caps the number of paid calls at what the page can show. Any other spelling of
 * the query (lower case, spaces, extra parameters) is redirected to that one
 * URL, so the CDN holds a single copy per CVE and can't be bypassed.
 */
export function createExplainHandler({
  loadCatalog = createCatalogLoader(),
  explain = defaultExplain(),
  configured = () => explainConfigured(),
  now = () => new Date(),
} = {}) {
  return async function handler(request) {
    if (request.method !== 'GET') return json({ error: 'Method not allowed' }, 405);
    const url = new URL(request.url);
    const cveID = (url.searchParams.get('cve') || '').trim().toUpperCase();
    if (!CVE_PATTERN.test(cveID)) return json({ error: 'Expected ?cve=CVE-YYYY-NNNN' }, 400);
    const canonical = `?cve=${cveID}`;
    if (url.search !== canonical) {
      return new Response(null, {
        status: 308,
        headers: { location: `${url.pathname}${canonical}`, 'cache-control': REDIRECT_CACHE_CONTROL },
      });
    }
    if (!configured()) return json({ error: 'Explanations are not configured on this server.' }, 503);

    let entry;
    try {
      const { catalog } = await loadCatalog();
      entry = findEntry(catalog, cveID);
    } catch (err) {
      console.error('Failed to load KEV feed:', err);
      return json({ error: 'The CISA KEV feed could not be loaded.' }, 502);
    }
    if (!entry) return json({ error: `${cveID} is not in the KEV catalog.` }, 404, 'public, max-age=0, s-maxage=300');
    if (!inWindow(entry.dateAdded, { now: now(), days: EXPLAIN_WINDOW_DAYS })) {
      return json(
        { error: `${cveID} was not added to the KEV catalog in the last ${WINDOW_DAYS} days.` },
        404,
        'public, max-age=0, s-maxage=300',
      );
    }

    try {
      const sentences = await explain(entry);
      return json({ cveID, sentences }, 200, EXPLAIN_CACHE_CONTROL);
    } catch (err) {
      console.error(`Failed to explain ${cveID}:`, err);
      return json({ error: 'An explanation could not be generated. Please try again shortly.' }, 502);
    }
  };
}
