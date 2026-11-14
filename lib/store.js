// Durable storage for finished explanations in Vercel Blob. The in-memory
// cache in lib/explain.js only lives as long as one function instance; this
// store is shared by every instance and survives redeploys, so each CVE is
// sent to Claude once in total.

const PREFIX = 'explanations/';
const STORE_TIMEOUT_MS = 5_000;

/**
 * True when the deployment can reach a Blob store. Connecting a store to the
 * Vercel project sets one of these: BLOB_READ_WRITE_TOKEN, or BLOB_STORE_ID
 * (used with the function's own OIDC token).
 */
export function blobConfigured(env = process.env) {
  return Boolean(env.BLOB_READ_WRITE_TOKEN || env.BLOB_STORE_ID);
}

const isSentences = (s) => Array.isArray(s) && s.length === 3 && s.every((x) => typeof x === 'string' && x.trim());

/**
 * Returns { get(cveID) -> sentences | undefined, set(cveID, sentences) }.
 * `blob` is the @vercel/blob module (or a fake in tests). `access` must match
 * the store's own setting, public or private; private is the default because
 * nothing needs the stored files except this function.
 */
export function createBlobStore({ blob, access = process.env.KEV_BLOB_ACCESS || 'private' } = {}) {
  const pathFor = (cveID) => `${PREFIX}${cveID}.json`;

  return {
    async get(cveID) {
      const result = await blob.get(pathFor(cveID), {
        access,
        abortSignal: AbortSignal.timeout(STORE_TIMEOUT_MS),
      });
      if (!result || result.statusCode !== 200) return undefined;
      const data = await new Response(result.stream).json().catch(() => null);
      // A damaged file counts as missing; the fresh answer overwrites it.
      return isSentences(data?.sentences) ? data.sentences : undefined;
    },

    async set(cveID, sentences, meta = {}) {
      const body = JSON.stringify({ cveID, sentences, ...meta, createdAt: new Date().toISOString() });
      await blob.put(pathFor(cveID), body, {
        access,
        contentType: 'application/json',
        addRandomSuffix: false,
        // Two instances can race on the same CVE; either answer is fine.
        allowOverwrite: true,
        abortSignal: AbortSignal.timeout(STORE_TIMEOUT_MS),
      });
    },
  };
}

/** A store that keeps nothing between instances, for local development. */
export function createMemoryStore() {
  const map = new Map();
  return {
    async get(cveID) { return map.get(cveID); },
    async set(cveID, sentences) { map.set(cveID, sentences); },
  };
}
