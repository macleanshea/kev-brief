# kev-brief

A public page listing the security vulnerabilities the US government has most
recently confirmed are being exploited: every entry added to
[CISA's Known Exploited Vulnerabilities (KEV) catalog](https://www.cisa.gov/known-exploited-vulnerabilities-catalog)
in the last 14 days, newest first, with vendor, product, date added and
whether ransomware use is known.

Each entry has an **Explain** button that fetches a three-sentence,
plain-language explanation written by Claude: what the product is, what an
attacker can do, and who should care.

## Why this setup

The page needs two things beyond static hosting: a server-side function that
fetches the KEV feed and caches it, and one that asks Claude to explain an
entry. So the project is **two Vercel Functions in `api/` with no framework and
two dependencies** (the Anthropic SDK and the Vercel Blob SDK).

- **No framework.** Next.js, Astro or SvelteKit would all work, but they bring a
  build step, a dependency tree and a router to serve one page. Vercel runs any
  file in `api/` as a Node.js function with zero configuration, so that is all
  this needs. `vercel.json` has one rewrite so the page is served at `/`.
- **Server-rendered HTML.** The function returns the finished page. The only
  client JavaScript is a small inline script for the Explain buttons; the
  browser never fetches anything from CISA.
- **Two dependencies.** Node's built-in `fetch`, `Request`/`Response` and test
  runner (`node --test`) cover everything except calling Claude
  (`@anthropic-ai/sdk`) and saving its answers (`@vercel/blob`).

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

### Explanations

`GET /api/explain?cve=CVE-YYYY-NNNN` returns
`{ "cveID": "...", "sentences": [product, attacker, audience] }`.

- The browser sends only a CVE ID. The server looks the CVE up in the KEV
  feed (404 if it isn't there) and gives Claude only CISA's own fields for it
  (vendor, product, vulnerability name, description, ransomware use), so the
  endpoint can't be used to ask Claude arbitrary questions.
- Claude returns structured JSON with exactly one sentence per field. The
  system prompt asks for outcomes, not exploitation detail. The request opts
  into server-side refusal fallbacks, so if a safety classifier declines, the
  API retries on a fallback model instead of failing.
- Each explanation is paid for once per CVE. Answers are saved in a
  [Vercel Blob](https://vercel.com/docs/vercel-blob) store
  (`explanations/CVE-….json`), which every function instance shares and which
  survives redeploys. A request checks memory, then Blob, and only then calls
  Claude. If Blob can't be read, the request fails rather than risk paying
  twice.
- Each CVE has one URL. Any other form (lower case, spaces, extra
  parameters) is redirected to `/api/explain?cve=CVE-…`, so the CDN keeps one
  copy per CVE for a week
  (`Cache-Control: public, max-age=0, s-maxage=604800, stale-while-revalidate=86400`).
- Failures are not stored. The same instance repeats a failure for a minute
  before trying again, so clicking a failing entry over and over doesn't cost
  extra.
- Two instances that miss the same CVE at the same moment can each call
  Claude once. That's the only way an entry costs more than one call.
- Each call to Claude times out after 20 seconds and is retried once. The
  function may run for 60 seconds (`vercel.json`). The browser stops waiting
  after 65 seconds. Every failure shows a message under the row and a
  **Retry** button: timeouts, an unreachable server, a 504 from the platform,
  and errors from the feed or Claude.
- Explanations need `ANTHROPIC_API_KEY`, and on Vercel also a connected Blob
  store. Without them the page still works; Explain shows an error and the
  endpoint returns 503.

### "Last 14 days"

KEV's `dateAdded` is a calendar date with no time, so the window is 14 calendar
days in UTC including today: on 2026-11-14 the page shows entries dated
2026-11-01 through 2026-11-14.

## Layout

| Path | Purpose |
| --- | --- |
| `api/index.js` | The page's Vercel Function entry point (Web `fetch` handler) |
| `api/explain.js` | The Explain endpoint's Vercel Function entry point |
| `lib/kev.js` | Fetching and caching the feed, filtering, HTML rendering, the Explain button script |
| `lib/explain.js` | Prompt, Claude call, timeouts and caching for explanations |
| `lib/store.js` | Saving explanations in Vercel Blob (or memory, locally) |
| `lib/handler.js` | Turns requests into responses, sets cache headers |
| `test/kev.test.js`, `test/explain.test.js` | Tests |
| `test/fixtures/kev-sample.json` | A saved copy of the real feed (catalog 2026.11.13, entries since 2026-07-01) |
| `.github/workflows/test.yml` | Runs the tests on every pull request and on pushes to `main` |

## Running locally

```bash
npm install
```

```bash
npm test
```

```bash
npx vercel dev
```

`KEV_FEED_URL` overrides the feed location, for example to use CISA's GitHub
mirror (`https://raw.githubusercontent.com/cisagov/kev-data/main/known_exploited_vulnerabilities.json`).
`ANTHROPIC_API_KEY` enables the Explain buttons, and `KEV_EXPLAIN_MODEL`
overrides the Claude model (default `claude-opus-5-5`). Locally, explanations
are kept in memory unless `BLOB_READ_WRITE_TOKEN` is set. `KEV_BLOB_ACCESS`
must match the Blob store's access setting (`private`, the default, or
`public`).

## Deploying

1. Import the repository in Vercel. No build command or output directory is
   needed.
2. Set `ANTHROPIC_API_KEY` in the project's environment variables.
3. Create a **private** Blob store (Storage → Create → Blob) and connect it to
   the project. That sets the store's credentials for the functions. Explain
   stays off on Vercel until a store is connected.

## Tests

The tests never touch the network. They run against the saved sample of the
feed, a fake `fetch`, a fake Claude client and a fake Blob store. They cover
the Explain endpoint (input validation, redirects to the standard URL, unknown
CVEs, missing configuration, errors, timeouts, the stored and in-memory caches,
the failure cooldown, refusals, escaping), and the 14-day window and its edges, newest-first
ordering, the ransomware flag, HTML escaping, the empty state, cache expiry,
falling back to a stale copy, and the response headers.

To refresh the sample, download the feed and keep recent entries; tests that
depend on specific dates pass `now` explicitly, so update those dates too.
