// Vercel Function: GET /api/explain?cve=CVE-YYYY-NNNN returns a three-sentence
// plain-language explanation of a KEV entry as JSON.
import { createExplainHandler } from '../lib/handler.js';

const handler = createExplainHandler();

export default {
  fetch(request) {
    return handler(request);
  },
};
