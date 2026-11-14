import { createCatalogLoader, recentEntries, renderPage, CACHE_TTL_MS } from './kev.js';

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
