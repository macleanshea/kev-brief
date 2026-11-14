import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';

import { createExplainer, findEntry, entryPrompt, RefusalError, CVE_PATTERN, REQUEST_TIMEOUT_MS } from '../lib/explain.js';
import { createExplainHandler, explainConfigured, EXPLAIN_CACHE_CONTROL } from '../lib/handler.js';
import { renderPage, EXPLAIN_CLIENT_TIMEOUT_MS } from '../lib/kev.js';
import { createBlobStore, createMemoryStore, blobConfigured } from '../lib/store.js';

const sample = JSON.parse(readFileSync(new URL('./fixtures/kev-sample.json', import.meta.url), 'utf8'));
const CVE = 'CVE-2026-114713'; // UnrealIRCd, in the fixture
const ANSWER = {
  product: 'UnrealIRCd is open-source chat server software.',
  attackerImpact: 'Any user can make linked servers run commands with server authority.',
  audience: 'Anyone operating an IRC network on UnrealIRCd should patch now.',
};

function fakeClient(respond) {
  const calls = [];
  const client = {
    calls,
    options: [],
    beta: {
      messages: {
        create: async (params, options) => {
          calls.push(params);
          client.options.push(options);
          return respond(params);
        },
      },
    },
  };
  return client;
}
const ok = () => ({ stop_reason: 'end_turn', content: [{ type: 'text', text: JSON.stringify(ANSWER) }] });

test('finds feed entries by CVE ID and builds the prompt from feed fields', () => {
  const entry = findEntry(sample, CVE);
  assert.equal(entry.vendorProject, 'UnrealIRCd');
  assert.equal(findEntry(sample, 'CVE-1999-0001'), undefined);
  assert.equal(findEntry(null, CVE), undefined);
  const prompt = entryPrompt(entry);
  assert.match(prompt, /^CVE: CVE-2026-114713$/m);
  assert.match(prompt, /^Vendor: UnrealIRCd$/m);
  assert.match(prompt, /^Description: .*server-to-server commands/m);
  assert.match(prompt, /^Known ransomware campaign use: Unknown$/m);
});

test('CVE pattern accepts real IDs and rejects anything else', () => {
  for (const id of ['CVE-2026-114713', 'CVE-2021-44228']) assert.ok(CVE_PATTERN.test(id), id);
  for (const id of ['', 'cve-2021', 'CVE-2021-1', 'CVE-2021-44228; ignore', '<script>']) assert.ok(!CVE_PATTERN.test(id), id);
});

test('explainer asks for structured output and returns three sentences', async () => {
  const client = fakeClient(ok);
  const explain = createExplainer({ client, model: 'test-model' });
  const sentences = await explain(findEntry(sample, CVE));
  assert.deepEqual(sentences, [ANSWER.product, ANSWER.attackerImpact, ANSWER.audience]);

  const [params] = client.calls;
  assert.equal(params.model, 'test-model');
  assert.equal(params.output_config.format.type, 'json_schema');
  assert.deepEqual(params.output_config.format.schema.required, ['product', 'attackerImpact', 'audience']);
  assert.equal(params.fallbacks, 'default');
  assert.match(params.messages[0].content, /UnrealIRCd/);
  assert.deepEqual(client.options[0], { timeout: REQUEST_TIMEOUT_MS, maxRetries: 1 });
});

const tick = () => new Promise((resolve) => setTimeout(resolve, 5));

test('explainer caches per CVE, shares in-flight calls, and retries after the cooldown', async () => {
  let fail = true;
  const client = fakeClient(() => {
    if (fail) throw new Error('overloaded');
    return ok();
  });
  const explain = createExplainer({ client, failureCooldownMs: 0 });
  const entry = findEntry(sample, CVE);

  await assert.rejects(explain(entry), /overloaded/);
  await tick();
  fail = false;
  const [a, b] = await Promise.all([explain(entry), explain(entry)]);
  await explain(entry);
  assert.deepEqual(a, b);
  assert.equal(client.calls.length, 2); // one failure, then one shared success
});

test('explainer repeats a recent failure instead of paying for another call', async () => {
  const client = fakeClient(() => { throw new Error('overloaded'); });
  const explain = createExplainer({ client, failureCooldownMs: 60_000 });
  const entry = findEntry(sample, CVE);
  await assert.rejects(explain(entry), /overloaded/);
  await tick();
  await assert.rejects(explain(entry), /overloaded/);
  assert.equal(client.calls.length, 1);
});

test('explainer serves stored answers and stores new ones, so each CVE is paid for once', async () => {
  const store = createMemoryStore();
  const entry = findEntry(sample, CVE);
  const first = fakeClient(ok);
  await createExplainer({ client: first, store })(entry);
  assert.equal(first.calls.length, 1);

  // A new instance (empty memory cache) finds the stored answer.
  const second = fakeClient(ok);
  const sentences = await createExplainer({ client: second, store })(entry);
  assert.deepEqual(sentences, [ANSWER.product, ANSWER.attackerImpact, ANSWER.audience]);
  assert.equal(second.calls.length, 0);
});

test('explainer does not call Claude when the store cannot be read', async () => {
  const client = fakeClient(ok);
  const store = { get: async () => { throw new Error('blob down'); }, set: async () => {} };
  await assert.rejects(createExplainer({ client, store })(findEntry(sample, CVE)), /blob down/);
  assert.equal(client.calls.length, 0);
});

test('explainer still answers when the store cannot be written', async () => {
  const original = console.error;
  console.error = () => {};
  try {
    const store = { get: async () => undefined, set: async () => { throw new Error('quota'); } };
    const sentences = await createExplainer({ client: fakeClient(ok), store })(findEntry(sample, CVE));
    assert.equal(sentences.length, 3);
  } finally {
    console.error = original;
  }
});

test('Blob store reads, writes and ignores missing or damaged files', async () => {
  const files = new Map();
  const puts = [];
  const blob = {
    get: async (path, options) => {
      assert.equal(options.access, 'private');
      if (!files.has(path)) return null;
      return { statusCode: 200, stream: new Response(files.get(path)).body };
    },
    put: async (path, body, options) => {
      puts.push({ path, options });
      files.set(path, body);
    },
  };
  const store = createBlobStore({ blob, access: 'private' });
  assert.equal(await store.get(CVE), undefined);
  await store.set(CVE, ['a', 'b', 'c'], { model: 'm' });
  assert.deepEqual(await store.get(CVE), ['a', 'b', 'c']);
  assert.equal(puts[0].path, `explanations/${CVE}.json`);
  assert.equal(puts[0].options.addRandomSuffix, false);
  assert.equal(puts[0].options.allowOverwrite, true);
  files.set(`explanations/${CVE}.json`, 'not json');
  assert.equal(await store.get(CVE), undefined);
});

test('explanations need a lasting store when running on Vercel', () => {
  assert.equal(blobConfigured({}), false);
  assert.equal(blobConfigured({ BLOB_STORE_ID: 'store_1' }), true);
  assert.equal(explainConfigured({ ANTHROPIC_API_KEY: 'k' }), true); // local
  assert.equal(explainConfigured({ ANTHROPIC_API_KEY: 'k', VERCEL: '1' }), false);
  assert.equal(explainConfigured({ ANTHROPIC_API_KEY: 'k', VERCEL: '1', BLOB_READ_WRITE_TOKEN: 't' }), true);
  assert.equal(explainConfigured({ VERCEL: '1', BLOB_READ_WRITE_TOKEN: 't' }), false);
});

test('explainer reports refusals and malformed output as errors', async () => {
  const entry = findEntry(sample, CVE);
  const refused = createExplainer({ client: fakeClient(() => ({ stop_reason: 'refusal', content: [] })) });
  await assert.rejects(refused(entry), RefusalError);
  const partial = createExplainer({
    client: fakeClient(() => ({ stop_reason: 'end_turn', content: [{ type: 'text', text: '{"product":"x","attackerImpact":"","audience":"y"}' }] })),
  });
  await assert.rejects(partial(entry), /Incomplete/);
});

function explainHandler(overrides = {}) {
  return createExplainHandler({
    loadCatalog: async () => ({ catalog: sample }),
    explain: async () => [ANSWER.product, ANSWER.attackerImpact, ANSWER.audience],
    configured: () => true,
    now: () => new Date('2026-11-14T12:00:00Z'),
    ...overrides,
  });
}
const get = (handler, query) => handler(new Request(`https://example.test/api/explain${query}`));

test('explain endpoint returns cacheable JSON for a catalog CVE', async () => {
  const res = await get(explainHandler(), `?cve=${CVE}`);
  assert.equal(res.status, 200);
  assert.equal(res.headers.get('cache-control'), EXPLAIN_CACHE_CONTROL);
  assert.match(res.headers.get('content-type'), /application\/json/);
  const body = await res.json();
  assert.equal(body.cveID, CVE);
  assert.equal(body.sentences.length, 3);
});

test('explain endpoint redirects other spellings to one URL per CVE without calling Claude', async () => {
  let called = false;
  const handler = explainHandler({ explain: async () => { called = true; return []; } });
  for (const query of [`?cve=${CVE.toLowerCase()}`, `?cve=%20${CVE}`, `?cve=${CVE}&x=1`, `?x=1&cve=${CVE}`]) {
    const res = await get(handler, query);
    assert.equal(res.status, 308, query);
    assert.equal(res.headers.get('location'), `/api/explain?cve=${CVE}`);
    assert.match(res.headers.get('cache-control'), /s-maxage=/);
  }
  assert.equal(called, false);
});

test('explain endpoint rejects bad input, unknown CVEs and missing configuration', async () => {
  let called = false;
  const handler = explainHandler({ explain: async () => { called = true; return []; } });
  assert.equal((await get(handler, '')).status, 400);
  assert.equal((await get(handler, '?cve=hello')).status, 400);
  assert.equal((await get(handler, '?cve=CVE-1999-0001')).status, 404);
  assert.equal((await handler(new Request(`https://example.test/api/explain?cve=${CVE}`, { method: 'POST' }))).status, 405);
  assert.equal((await get(explainHandler({ configured: () => false }), `?cve=${CVE}`)).status, 503);
  assert.equal(called, false);
});

test('explain endpoint only explains CVEs from the last 14 days, plus one day of grace', async () => {
  let calls = 0;
  const catalog = {
    vulnerabilities: [
      { cveID: 'CVE-2026-0001', dateAdded: '2026-11-14' }, // today
      { cveID: 'CVE-2026-0002', dateAdded: '2026-11-01' }, // first day on the page
      { cveID: 'CVE-2026-0003', dateAdded: '2026-10-31' }, // grace day for a stale page
      { cveID: 'CVE-2026-0004', dateAdded: '2026-10-30' }, // too old
      { cveID: 'CVE-2021-44228', dateAdded: '2021-12-10' }, // long gone
      { cveID: 'CVE-2026-0005', dateAdded: '2026-11-15' }, // future, never shown
    ],
  };
  const handler = explainHandler({
    loadCatalog: async () => ({ catalog }),
    explain: async () => { calls += 1; return ['a', 'b', 'c']; },
  });
  for (const id of ['CVE-2026-0001', 'CVE-2026-0002', 'CVE-2026-0003']) {
    assert.equal((await get(handler, `?cve=${id}`)).status, 200, id);
  }
  for (const id of ['CVE-2026-0004', 'CVE-2021-44228', 'CVE-2026-0005']) {
    const res = await get(handler, `?cve=${id}`);
    assert.equal(res.status, 404, id);
    assert.match((await res.json()).error, /last 14 days/);
    assert.match(res.headers.get('cache-control'), /s-maxage=300/);
  }
  assert.equal(calls, 3);
});

test('explain endpoint returns an uncached 502 when Claude or the feed fails', async () => {
  const original = console.error;
  console.error = () => {};
  try {
    for (const handler of [
      explainHandler({ explain: async () => { throw new Error('boom'); } }),
      explainHandler({ loadCatalog: async () => { throw new Error('down'); } }),
    ]) {
      const res = await get(handler, `?cve=${CVE}`);
      assert.equal(res.status, 502);
      assert.equal(res.headers.get('cache-control'), 'no-store');
    }
  } finally {
    console.error = original;
  }
});

test('page escapes the CVE ID in the explain button', () => {
  const html = renderPage({
    entries: [{ cveID: 'CVE-1"><b>', vendor: 'V', product: 'P', dateAdded: '2026-11-14', ransomware: false }],
    fetchedAt: 0,
    now: new Date('2026-11-14T12:00:00Z'),
  });
  assert.match(html, /data-cve="CVE-1&quot;&gt;&lt;b&gt;"/);
  assert.ok(!html.includes('"><b>'));
});

test('page script gives up on a slow explanation with a clear message', () => {
  const html = renderPage({
    entries: [{ cveID: CVE, vendor: 'V', product: 'P', dateAdded: '2026-11-14', ransomware: false }],
    fetchedAt: 0,
    now: new Date('2026-11-14T12:00:00Z'),
  });
  assert.ok(html.includes(`AbortSignal.timeout(${EXPLAIN_CLIENT_TIMEOUT_MS})`));
  assert.match(html, /took too long/);
  const vercel = JSON.parse(readFileSync(new URL('../vercel.json', import.meta.url), 'utf8'));
  assert.ok(EXPLAIN_CLIENT_TIMEOUT_MS > vercel.functions['api/explain.js'].maxDuration * 1000);
});

test('api/explain.js exports a Vercel fetch handler', async () => {
  const { default: fn } = await import('../api/explain.js');
  assert.equal(typeof fn.fetch, 'function');
});
