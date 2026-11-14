// Plain-language explanations of KEV entries, written by Claude. The client
// sends only a CVE ID; everything Claude sees comes from CISA's feed, so the
// endpoint can't be used to ask Claude arbitrary questions.

export const EXPLAIN_MODEL = process.env.KEV_EXPLAIN_MODEL || 'claude-opus-5-5';
export const CVE_PATTERN = /^CVE-\d{4}-\d{4,}$/;

const SYSTEM_PROMPT = `You write short, plain-language briefings about vulnerabilities in CISA's Known Exploited Vulnerabilities catalog for a general technical audience.

You are given one catalog entry. Return exactly three sentences, one per field:
- product: what the product is and what it is typically used for.
- attackerImpact: what an attacker who exploits this vulnerability can do, at the level of outcome (for example "run code on the server" or "read other users' files"). Never give exploitation steps, payloads or technical detail that would help someone attack it.
- audience: who should care, such as the kinds of organizations or teams that run this product and should check for exposure and patch.

Each field is one complete sentence of at most about 35 words, with no markdown. Base the facts about the vulnerability on the entry; you may use general knowledge to describe the product. If the entry doesn't say something, don't invent specifics.`;

const SCHEMA = {
  type: 'object',
  properties: {
    product: { type: 'string', description: 'One sentence: what the product is.' },
    attackerImpact: { type: 'string', description: 'One sentence: what an attacker can do.' },
    audience: { type: 'string', description: 'One sentence: who should care.' },
  },
  required: ['product', 'attackerImpact', 'audience'],
  additionalProperties: false,
};

export class NotFoundError extends Error {}
export class RefusalError extends Error {}

/** The raw feed record for a CVE, or undefined. */
export function findEntry(catalog, cveID) {
  const vulns = Array.isArray(catalog?.vulnerabilities) ? catalog.vulnerabilities : [];
  return vulns.find((v) => v.cveID === cveID);
}

/** The user message describing one feed record. */
export function entryPrompt(v) {
  const fields = [
    ['CVE', v.cveID],
    ['Vendor', v.vendorProject],
    ['Product', v.product],
    ['Vulnerability name', v.vulnerabilityName],
    ['Description', v.shortDescription],
    ['Known ransomware campaign use', v.knownRansomwareCampaignUse],
    ['Date added to KEV', v.dateAdded],
  ];
  return fields
    .filter(([, value]) => typeof value === 'string' && value.trim())
    .map(([label, value]) => `${label}: ${value.trim()}`)
    .join('\n');
}

/**
 * Returns explain(entry) -> Promise<[product, attackerImpact, audience]>.
 * Results (and in-flight requests) are kept in memory per CVE, so warm
 * instances call the API at most once per CVE. Failures are not cached.
 */
export function createExplainer({ client, model = EXPLAIN_MODEL } = {}) {
  const cache = new Map();

  async function generate(entry) {
    const response = await client.beta.messages.create({
      model,
      max_tokens: 2000,
      // On a safety-classifier decline the API re-runs the request on a
      // fallback model instead of returning a refusal.
      betas: ['server-side-fallback-2026-07-01'],
      fallbacks: 'default',
      output_config: { effort: 'low', format: { type: 'json_schema', schema: SCHEMA } },
      system: SYSTEM_PROMPT,
      messages: [{ role: 'user', content: entryPrompt(entry) }],
    });
    if (response.stop_reason === 'refusal') throw new RefusalError(`Model declined to explain ${entry.cveID}`);
    if (response.stop_reason === 'max_tokens') throw new Error(`Explanation for ${entry.cveID} was cut off`);
    const text = response.content.find((b) => b.type === 'text')?.text;
    if (!text) throw new Error(`No text in response for ${entry.cveID}`);
    const parsed = JSON.parse(text);
    const sentences = [parsed.product, parsed.attackerImpact, parsed.audience].map((s) => String(s ?? '').trim());
    if (sentences.some((s) => !s)) throw new Error(`Incomplete explanation for ${entry.cveID}`);
    return sentences;
  }

  return function explain(entry) {
    let pending = cache.get(entry.cveID);
    if (!pending) {
      pending = generate(entry);
      cache.set(entry.cveID, pending);
      pending.catch(() => cache.delete(entry.cveID));
    }
    return pending;
  };
}
