import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';

import { createExplainer, findEntry, entryPrompt, RefusalError, CVE_PATTERN } from '../lib/explain.js';
import { createExplainHandler, EXPLAIN_CACHE_CONTROL } from '../lib/handler.js';
import { renderPage } from '../lib/kev.js';

const sample = JSON.parse(readFileSync(new URL('./fixtures/kev-sample.json', import.meta.url), 'utf8'));
const CVE = 'CVE-2026-114713'; // UnrealIRCd, in the fixture
const ANSWER = {
  product: 'UnrealIRCd is open-source chat server software.',
  attackerImpact: 'Any user can make linked servers run commands with server authority.',
  audience: 'Anyone operating an IRC network on UnrealIRCd should patch now.',
};

function fakeClient(respond) {
  const calls = [];
  return {
    calls,
    beta: { messages: { create: async (params) => { calls.push(params); return respond(params); } } },
  };
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
});

test('explainer caches per CVE, shares in-flight calls, and retries after failure', async () => {
  let fail = true;
  const client = fakeClient(() => {
    if (fail) throw new Error('overloaded');
    return ok();
  });
  const explain = createExplainer({ client });
  const entry = findEntry(sample, CVE);

  await assert.rejects(explain(entry), /overloaded/);
  fail = false;
  const [a, b] = await Promise.all([explain(entry), explain(entry)]);
  await explain(entry);
  assert.deepEqual(a, b);
  assert.equal(client.calls.length, 2); // one failure, then one shared success
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
    ...overrides,
  });
}
const get = (handler, query) => handler(new Request(`https://example.test/api/explain${query}`));

test('explain endpoint returns cacheable JSON for a catalog CVE', async () => {
  const res = await get(explainHandler(), `?cve=${CVE.toLowerCase()}`);
  assert.equal(res.status, 200);
  assert.equal(res.headers.get('cache-control'), EXPLAIN_CACHE_CONTROL);
  assert.match(res.headers.get('content-type'), /application\/json/);
  const body = await res.json();
  assert.equal(body.cveID, CVE);
  assert.equal(body.sentences.length, 3);
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

test('api/explain.js exports a Vercel fetch handler', async () => {
  const { default: fn } = await import('../api/explain.js');
  assert.equal(typeof fn.fetch, 'function');
});
