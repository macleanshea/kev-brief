// Vercel Function (Node.js runtime, Web signature). Served at /api and, via
// the rewrite in vercel.json, at /.
import { createHandler } from '../lib/handler.js';

const handler = createHandler();

export default {
  fetch(request) {
    return handler(request);
  },
};
