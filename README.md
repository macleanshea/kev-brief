# kev-brief

A public page listing the security vulnerabilities the US government has most
recently confirmed are being exploited: every entry added to
[CISA's Known Exploited Vulnerabilities (KEV) catalog](https://www.cisa.gov/known-exploited-vulnerabilities-catalog)
in the last 14 days, newest first, with vendor, product, date added and
whether ransomware use is known.

## Why this setup

The page needs exactly one thing beyond static hosting: a server-side function
that fetches the KEV feed and caches it. So the project is **a single Vercel
Function in `api/` with no framework and no dependencies**.

- **No framework.** Next.js, Astro or SvelteKit would all work, but they bring a
  build step, a dependency tree and a router to serve one page. Vercel runs any
  file in `api/` as a Node.js function with zero configuration, so that is all
  this needs. `vercel.json` has one rewrite so the page is served at `/`.
- **Server-rendered HTML.** The function returns the finished page, so there is
  no client JavaScript, no separate JSON endpoint and nothing for the browser to
  fetch from CISA.
- **No dependencies.** Node's built-in `fetch`, `Request`/`Response` and test
  runner (`node --test`) cover everything, so there is nothing to install,
  audit or keep up to date. `package.json` exists only to mark the code as ES
  modules and to define `npm test`.

### Caching

The feed is cached for 3 hours in two layers:

1. **Vercel's CDN.** Responses carry
   `Cache-Control: public, max-age=0, s-maxage=10800, stale-while-revalidate=3600`,
   so most visitors get a cached page without the function running at all, and
   after 3 hours the CDN serves the old copy while refreshing in the background.
2. **In memory in the function.** Warm function instances keep the parsed feed
   for 3 hours, so a CDN miss (new region, new deployment) usually doesn't need
   a new download of the ~2 MB feed.

If CISA is unreachable and an in-memory copy exists, the older copy is shown
and cached by the CDN for only 5 minutes. With no copy at all the page returns
a 502 that is never cached.

### "Last 14 days"

KEV's `dateAdded` is a calendar date with no time, so the window is 14 calendar
days in UTC including today: on 2026-11-14 the page shows entries dated
2026-11-01 through 2026-11-14.

## Layout

| Path | Purpose |
| --- | --- |
| `api/index.js` | The Vercel Function entry point (Web `fetch` handler) |
| `lib/kev.js` | Fetching and caching the feed, filtering, HTML rendering |
| `lib/handler.js` | Turns a request into a response, sets cache headers |
| `test/kev.test.js` | Tests |
| `test/fixtures/kev-sample.json` | A saved copy of the real feed (catalog 2026.11.13, entries since 2026-07-01) |
| `.github/workflows/test.yml` | Runs the tests on every pull request and on pushes to `main` |

## Running locally

```bash
npm test
```

```bash
npx vercel dev
```

`KEV_FEED_URL` overrides the feed location, for example to use CISA's GitHub
mirror (`https://raw.githubusercontent.com/cisagov/kev-data/main/known_exploited_vulnerabilities.json`).

## Deploying

Import the repository in Vercel. No build command, output directory or
environment variables are needed.

## Tests

The tests never touch the network. They run against the saved sample of the
feed and a fake `fetch`, and cover the 14-day window and its edges, newest-first
ordering, the ransomware flag, HTML escaping, the empty state, cache expiry,
falling back to a stale copy, and the response headers.

To refresh the sample, download the feed and keep recent entries; tests that
depend on specific dates pass `now` explicitly, so update those dates too.
