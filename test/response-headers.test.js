// Every response path carries the safety headers from mediaResponse(), and a migrated slug
// ("migrated:<slug>" in HOSTMAP) never falls back to the shared bucket. The R2 S3 endpoint is
// stubbed at globalThis.fetch, as in fallback-flow.test.js.

import { test, beforeEach, afterEach } from "node:test";
import assert from "node:assert/strict";

import worker, { mediaResponse, migratedFlagKey } from "../src/index.js";

const SLUG = "acme";
const PER_SITE_BUCKET = `doubleyoup-media-${SLUG}`;
const SHARED_BUCKET = "doubleyoup-media";

function hostmapWith({ hostSlug = null, migratedSlugs = [] } = {}) {
  return {
    get: async (kvKey) => {
      if (kvKey.startsWith("migrated:")) {
        const slug = kvKey.slice("migrated:".length);
        if (migratedSlugs.includes(slug)) return "1";
        return null;
      }
      return hostSlug;
    },
  };
}

function envWith(hostmap) {
  return {
    SHARED_HOST: "media.doubleyoup.com",
    MEDIA_BUCKET: SHARED_BUCKET,
    R2_ACCOUNT_ID: "acct123",
    R2_S3_KEY: "AKIATEST",
    R2_S3_SECRET: "s3cr3t",
    HOSTMAP: hostmap,
  };
}

const ENV = envWith(hostmapWith());

const realFetch = globalThis.fetch;
const realWarn = console.warn;
const realError = console.error;
let upstreamCalls;

function stubUpstream(responses) {
  const queue = [...responses];
  globalThis.fetch = async (url, init) => {
    upstreamCalls.push({ url, method: init.method });
    assert.ok(queue.length > 0, `unexpected extra upstream request to ${url}`);
    return queue.shift();
  };
}

function bucketOf(call) {
  return new URL(call.url).pathname.split("/")[1];
}

function objectResponse(status, headers = {}) {
  const hasBody = status !== 304 && status !== 412;
  // A byte body, not a string: a string body would add a default text/plain content-type.
  const body = hasBody ? new TextEncoder().encode("BYTES") : null;
  return new Response(body, { status, headers: new Headers(headers) });
}

function s3ErrorResponse(status) {
  return new Response("<Error/>", { status, headers: { "content-type": "application/xml" } });
}

function assertBaseSafetyHeaders(response) {
  assert.equal(response.headers.get("x-content-type-options"), "nosniff");
  assert.equal(response.headers.get("access-control-allow-origin"), "*");
}

function assertInlineAllowed(response) {
  assert.equal(response.headers.get("content-disposition"), null);
  assert.equal(response.headers.get("content-security-policy"), null);
}

function assertSandboxedDownload(response) {
  assert.equal(response.headers.get("content-disposition"), "attachment");
  assert.equal(response.headers.get("content-security-policy"), "sandbox");
}

beforeEach(() => {
  upstreamCalls = [];
  console.warn = () => {};
  console.error = () => {};
});

afterEach(() => {
  globalThis.fetch = realFetch;
  console.warn = realWarn;
  console.error = realError;
});

// ── mediaResponse() ───────────────────────────────────────────────────────────

test("mediaResponse sets nosniff and CORS on a passive type and leaves it inline", () => {
  const response = mediaResponse("x", { status: 200, headers: new Headers({ "content-type": "image/png" }) });
  assertBaseSafetyHeaders(response);
  assertInlineAllowed(response);
});

const activeContentTypes = [
  "text/html",
  "text/html; charset=utf-8",
  "Text/HTML",
  "application/xhtml+xml",
  "image/svg+xml",
  "text/xml",
  "application/xml",
  "application/rss+xml",
  "text/xsl",
  // Comma-joined: a browser takes the last type, so this renders as HTML.
  "image/png, text/html",
  "image/png,text/html; charset=utf-8",
];

for (const contentType of activeContentTypes) {
  test(`mediaResponse sends ${contentType} as a sandboxed download`, () => {
    const response = mediaResponse("x", { status: 200, headers: new Headers({ "content-type": contentType }) });
    assertBaseSafetyHeaders(response);
    assertSandboxedDownload(response);
  });
}

test("mediaResponse sets nosniff when there is no content-type at all", () => {
  const response = mediaResponse(null, { status: 404, headers: new Headers() });
  assertBaseSafetyHeaders(response);
  assertInlineAllowed(response);
});

// ── every handler response path ──────────────────────────────────────────────

test("200 image: nosniff, inline", async () => {
  stubUpstream([objectResponse(200, { "content-type": "image/jpeg" })]);
  const response = await worker.fetch(new Request(`https://media.doubleyoup.com/${SLUG}/a.jpg`), ENV);
  assert.equal(response.status, 200);
  assertBaseSafetyHeaders(response);
  assertInlineAllowed(response);
});

test("200 HTML stored by a tenant: sandboxed download", async () => {
  stubUpstream([objectResponse(200, { "content-type": "text/html" })]);
  const response = await worker.fetch(new Request(`https://media.doubleyoup.com/${SLUG}/page.html`), ENV);
  assert.equal(response.status, 200);
  assertBaseSafetyHeaders(response);
  assertSandboxedDownload(response);
});

test("200 comma-joined content-type ending in HTML: sandboxed download", async () => {
  stubUpstream([objectResponse(200, { "content-type": "image/png, text/html" })]);
  const response = await worker.fetch(new Request(`https://media.doubleyoup.com/${SLUG}/x.png`), ENV);
  assert.equal(response.status, 200);
  assertBaseSafetyHeaders(response);
  assertSandboxedDownload(response);
});

test("200 SVG with no stored content-type (extension fallback): sandboxed download", async () => {
  stubUpstream([objectResponse(200)]);
  const response = await worker.fetch(new Request(`https://media.doubleyoup.com/${SLUG}/logo.svg`), ENV);
  assert.equal(response.status, 200);
  assert.equal(response.headers.get("content-type"), "image/svg+xml");
  assertBaseSafetyHeaders(response);
  assertSandboxedDownload(response);
});

test("206 range of an SVG: sandboxed download", async () => {
  stubUpstream([objectResponse(206, { "content-type": "image/svg+xml", "content-range": "bytes 0-1/5" })]);
  const request = new Request(`https://media.doubleyoup.com/${SLUG}/logo.svg`, { headers: { range: "bytes=0-1" } });
  const response = await worker.fetch(request, ENV);
  assert.equal(response.status, 206);
  assertBaseSafetyHeaders(response);
  assertSandboxedDownload(response);
});

for (const status of [304, 412]) {
  test(`${status} conditional answer: nosniff`, async () => {
    stubUpstream([objectResponse(status, { "content-type": "image/svg+xml" })]);
    const request = new Request(`https://media.doubleyoup.com/${SLUG}/logo.svg`, { headers: { "if-none-match": '"x"' } });
    const response = await worker.fetch(request, ENV);
    assert.equal(response.status, status);
    assertBaseSafetyHeaders(response);
  });
}

test("404: nosniff", async () => {
  stubUpstream([s3ErrorResponse(404), s3ErrorResponse(404)]);
  const response = await worker.fetch(new Request(`https://media.doubleyoup.com/${SLUG}/missing.jpg`), ENV);
  assert.equal(response.status, 404);
  assertBaseSafetyHeaders(response);
});

test("405: nosniff, allow header kept", async () => {
  const request = new Request(`https://media.doubleyoup.com/${SLUG}/a.jpg`, { method: "POST" });
  const response = await worker.fetch(request, ENV);
  assert.equal(response.status, 405);
  assert.equal(response.headers.get("allow"), "GET, HEAD");
  assertBaseSafetyHeaders(response);
});

test("400 malformed percent-encoding: nosniff", async () => {
  const response = await worker.fetch(new Request(`https://media.doubleyoup.com/${SLUG}/%E0%A4%A.jpg`), ENV);
  assert.equal(response.status, 400);
  assertBaseSafetyHeaders(response);
});

test("500 unexpected upstream status: nosniff", async () => {
  stubUpstream([s3ErrorResponse(500)]);
  const response = await worker.fetch(new Request(`https://media.doubleyoup.com/${SLUG}/a.jpg`), ENV);
  assert.equal(response.status, 500);
  assertBaseSafetyHeaders(response);
});

// ── migrated:<slug> turns the shared-bucket fallback off ──────────────────────

test("migratedFlagKey is migrated:<slug>", () => {
  assert.equal(migratedFlagKey(SLUG), "migrated:acme");
});

test("a migrated site's per-site 404 is final: the shared bucket is never read", async () => {
  stubUpstream([s3ErrorResponse(404)]);
  const env = envWith(hostmapWith({ migratedSlugs: [SLUG] }));
  const response = await worker.fetch(new Request(`https://media.doubleyoup.com/${SLUG}/deleted.jpg`), env);
  assert.equal(response.status, 404);
  assert.equal(upstreamCalls.length, 1);
  assert.equal(bucketOf(upstreamCalls[0]), PER_SITE_BUCKET);
});

test("a migrated site's per-site 403 surfaces as a 500, not a shared-bucket read", async () => {
  stubUpstream([s3ErrorResponse(403)]);
  const env = envWith(hostmapWith({ migratedSlugs: [SLUG] }));
  const response = await worker.fetch(new Request(`https://media.doubleyoup.com/${SLUG}/a.jpg`), env);
  assert.equal(response.status, 500);
  assert.equal(upstreamCalls.length, 1);
});

test("a migrated site on a branded host gets no fallback either", async () => {
  stubUpstream([s3ErrorResponse(404)]);
  const env = envWith(hostmapWith({ hostSlug: SLUG, migratedSlugs: [SLUG] }));
  const response = await worker.fetch(new Request("https://media.acme.example/deleted.jpg"), env);
  assert.equal(response.status, 404);
  assert.equal(upstreamCalls.length, 1);
});

test("a migrated site's staging miss reads the live key in the per-site bucket only", async () => {
  stubUpstream([s3ErrorResponse(404), objectResponse(200, { "content-type": "image/jpeg" })]);
  const env = envWith(hostmapWith({ migratedSlugs: [SLUG] }));
  const response = await worker.fetch(new Request(`https://media.doubleyoup.com/sg-${SLUG}/a.jpg`), env);
  assert.equal(response.status, 200);
  assert.equal(upstreamCalls.length, 2);
  assert.equal(bucketOf(upstreamCalls[0]), PER_SITE_BUCKET);
  assert.equal(bucketOf(upstreamCalls[1]), PER_SITE_BUCKET);
});

test("another site's migrated flag does not turn this site's fallback off", async () => {
  stubUpstream([s3ErrorResponse(404), objectResponse(200, { "content-type": "image/jpeg" })]);
  const env = envWith(hostmapWith({ migratedSlugs: ["other-site"] }));
  const response = await worker.fetch(new Request(`https://media.doubleyoup.com/${SLUG}/a.jpg`), env);
  assert.equal(response.status, 200);
  assert.equal(bucketOf(upstreamCalls[1]), SHARED_BUCKET);
});

test("a deployment with no HOSTMAP binding keeps the fallback", async () => {
  stubUpstream([s3ErrorResponse(404), objectResponse(200, { "content-type": "image/jpeg" })]);
  const env = envWith(undefined);
  const response = await worker.fetch(new Request(`https://media.doubleyoup.com/${SLUG}/a.jpg`), env);
  assert.equal(response.status, 200);
  assert.equal(bucketOf(upstreamCalls[1]), SHARED_BUCKET);
});

test("a migrated site's per-site 200 reads no KV flag", async () => {
  stubUpstream([objectResponse(200, { "content-type": "image/jpeg" })]);
  const kvKeysRead = [];
  const env = envWith({
    get: async (kvKey) => {
      kvKeysRead.push(kvKey);
      return "1";
    },
  });
  const response = await worker.fetch(new Request(`https://media.doubleyoup.com/${SLUG}/a.jpg`), env);
  assert.equal(response.status, 200);
  assert.deepEqual(kvKeysRead, []);
});
