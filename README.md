# kev-brief

**Live site: [kev-brief.vercel.app](https://kev-brief.vercel.app)**

A single page listing the vulnerabilities the US government has most recently
confirmed are being exploited: every entry added to
[CISA's Known Exploited Vulnerabilities (KEV) catalog](https://www.cisa.gov/known-exploited-vulnerabilities-catalog)
in the last 14 days, newest first, with vendor, product, CVE, date added and
whether ransomware use is known.

Each entry has an **Explain** button that shows a three-sentence,
plain-language summary written by Claude: what the product is, what an
attacker can do with the flaw, and who should care.

## How it works

Two Vercel Functions, no framework, no build step, two dependencies
(`@anthropic-ai/sdk` and `@vercel/blob`).

| Route | Function | What it does |
| --- | --- | --- |
| `/` (rewritten to `/api`) | `api/index.js` | Fetches the KEV feed and returns the finished HTML page |
| `/api/explain?cve=CVE-YYYY-NNNN` | `api/explain.js` | Returns `{ "cveID": "...", "sentences": [product, attacker, audience] }` |

The page is rendered on the server. The only client JavaScript is a small
inline script for the Explain buttons, and the browser never talks to CISA.

### The feed

- **Window:** KEV's `dateAdded` is a date with no time, so "last 14 days"
  means 14 calendar days in UTC including today. On 2026-11-14 the page shows
  entries dated 2026-11-01 through 2026-11-14.
- **Caching:** the CDN keeps the page for 3 hours
  (`s-maxage=10800, stale-while-revalidate=3600`), and warm function
  instances keep the parsed ~2 MB feed in memory for 3 hours.
- **If CISA is down:** an older in-memory copy is served and cached for only
  5 minutes. With no copy at all the page returns an uncached 502.

### Explanations

- The browser sends only a CVE ID. The server looks it up in the KEV feed and
  gives Claude only CISA's fields for that entry (vendor, product, name,
  description, ransomware use). A CVE that isn't in the catalog gets a 404, so
  the endpoint can't be used to ask Claude arbitrary questions.
- Claude returns structured JSON, one sentence per field. The system prompt
  asks for outcomes, not exploitation steps.
- Each CVE is paid for once. Answers are saved in a private
  [Vercel Blob](https://vercel.com/docs/vercel-blob) store
  (`explanations/CVE-….json`) that all instances share and that survives
  redeploys. A request checks memory, then Blob, then Claude. If Blob can't be
  read, the request fails rather than risk paying twice.
- Each CVE has one URL. Other spellings (lower case, extra parameters) are
  redirected to `/api/explain?cve=CVE-…`, which the CDN caches for a week.
- Failures aren't stored. An instance repeats a failure for a minute before
  trying again. Claude calls time out after 20 seconds and are retried once;
  the function may run for 60 seconds and the browser gives up at 65, then
  offers **Retry**.
- Without `ANTHROPIC_API_KEY` (and, on Vercel, a connected Blob store) the
  page still works and the endpoint returns 503.

## Security and abuse limits

- **Secrets:** none are in the repository or its history. The API key and
  Blob credentials live only in the Vercel project's environment variables.
- **Output:** all feed fields are HTML-escaped, and explanations are inserted
  with `textContent`, never as HTML.
- **Cost ceiling:** any CVE in the full catalog can be explained, not just
  those on the page. Someone requesting every one would cause roughly one
  Claude call per catalog entry (about 1,500), once; after that every answer
  is served from Blob or the CDN.
- **Known gaps:**
  - Two instances that miss the same CVE at the same moment can each call
    Claude, so a burst of parallel requests for an uncached CVE can cost more
    than one call.
  - There is no rate limit. Requests that skip the CDN (invalid IDs, a
    trailing slash on the path) still run the function, though they never
    reach Claude. A rate-limit rule in the Vercel Firewall would cap this.

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

| Variable | Purpose |
| --- | --- |
| `ANTHROPIC_API_KEY` | Enables Explain |
| `KEV_EXPLAIN_MODEL` | Claude model (default `claude-opus-5-5`) |
| `KEV_FEED_URL` | Feed location, e.g. CISA's GitHub mirror `https://raw.githubusercontent.com/cisagov/kev-data/main/known_exploited_vulnerabilities.json` |
| `BLOB_READ_WRITE_TOKEN` | Use Blob locally; otherwise explanations are kept in memory |
| `KEV_BLOB_ACCESS` | Must match the store's access setting: `private` (default) or `public` |

## Deploying

1. Import the repository in Vercel. No build command or output directory is
   needed.
2. Set `ANTHROPIC_API_KEY` in the project's environment variables.
3. Create a **private** Blob store (Storage → Create → Blob) and connect it to
   the project. Explain stays off on Vercel until a store is connected.

## Layout

| Path | Purpose |
| --- | --- |
| `api/index.js`, `api/explain.js` | Function entry points |
| `lib/kev.js` | Fetching and caching the feed, the 14-day filter, HTML rendering, the Explain button script |
| `lib/explain.js` | Prompt, Claude call, timeouts, in-memory cache and failure cooldown |
| `lib/store.js` | Saving explanations in Vercel Blob (or memory, locally) |
| `lib/handler.js` | Requests to responses, validation, redirects, cache headers |
| `test/` | Tests and a saved sample of the real feed (catalog 2026.11.13, entries since 2026-07-01) |
| `.github/workflows/test.yml` | Runs the tests on pull requests and pushes to `main` |

## Tests

```bash
npm test
```

The tests never touch the network: they use the saved feed sample, a fake
`fetch`, a fake Claude client and a fake Blob store. They cover the 14-day
window and its edges, ordering, escaping, cache expiry and stale fallback,
response headers, and for Explain: input validation, redirects, unknown CVEs,
missing configuration, timeouts, refusals, both caches and the failure
cooldown.

To refresh the sample, download the feed and keep recent entries. Tests that
depend on dates pass `now` explicitly, so update those dates too.
