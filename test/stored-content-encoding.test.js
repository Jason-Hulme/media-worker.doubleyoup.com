// hub#585: an R2 object that stores a Content-Encoding header over bytes that do not match
// it. In the Workers runtime fetch() decodes such a body itself; when the decode fails the
// stream errors or ends empty. The Worker must answer that with a logged, uncached 500, never
// with a 200 + 0-byte body + the 1-year immutable cache-control. The R2 S3 endpoint is stubbed
// at globalThis.fetch, and the stub's body simulates what the runtime's decode yields.

import { test, beforeEach, afterEach } from "node:test";
import assert from "node:assert/strict";

import worker from "../src/index.js";

const SLUG = "acme";
const CSS_URL = `https://media.doubleyoup.com/${SLUG}/elementor/google-fonts/css/font.css`;

const ENV = {
  SHARED_HOST: "media.doubleyoup.com",
  MEDIA_BUCKET: "doubleyoup-media",
  R2_ACCOUNT_ID: "acct123",
  R2_S3_KEY: "AKIATEST",
  R2_S3_SECRET: "s3cr3t",
  HOSTMAP: { get: async () => null },
};

const realFetch = globalThis.fetch;
const realWarn = console.warn;
let warnings;

function stubUpstream(response) {
  globalThis.fetch = async () => response;
}

// A body stream that fails on the first read, as the runtime's gunzip of plain bytes does.
function failingBodyStream() {
  return new ReadableStream({
    pull(controller) {
      controller.error(new TypeError("incorrect header check"));
    },
  });
}

function encodedObjectResponse({ status = 200, body, contentLength, extraHeaders = {} }) {
  const headers = new Headers({
    "content-type": "text/css; charset=utf-8",
    "content-encoding": "gzip",
    "content-length": contentLength,
    etag: '"abc123"',
    ...extraHeaders,
  });
  return new Response(body, { status, headers });
}

function mismatchWarnings() {
  return warnings.filter((line) => /stored-content-encoding-mismatch/.test(line));
}

beforeEach(() => {
  warnings = [];
  console.warn = (...args) => warnings.push(args.join(" "));
});

afterEach(() => {
  globalThis.fetch = realFetch;
  console.warn = realWarn;
});

function assertUncachedMismatch500(response) {
  assert.equal(response.status, 500);
  assert.notEqual(response.headers.get("cache-control"), "public, max-age=31536000, immutable");
  assert.equal(response.headers.get("cache-control"), null);
  assert.equal(mismatchWarnings().length, 1);
  assert.match(mismatchWarnings()[0], new RegExp(`key=${SLUG}/elementor/google-fonts/css/font.css`));
}

test("GET of an encoded object whose decode fails: logged 500, no immutable cache", async () => {
  stubUpstream(encodedObjectResponse({ body: failingBodyStream(), contentLength: "35184" }));

  const response = await worker.fetch(new Request(CSS_URL), ENV);

  assertUncachedMismatch500(response);
  assert.match(mismatchWarnings()[0], /reason=decode-failed/);
  assert.equal(await response.text(), "Internal error");
});

test("GET of an encoded object that decodes to 0 bytes while R2 promised bytes: logged 500", async () => {
  stubUpstream(encodedObjectResponse({ body: new Uint8Array(0), contentLength: "35184" }));

  const response = await worker.fetch(new Request(CSS_URL), ENV);

  assertUncachedMismatch500(response);
  assert.match(mismatchWarnings()[0], /reason=empty-body/);
});

test("GET of a correctly encoded object: 200 with the decoded bytes and their own length", async () => {
  const decodedCss = "body{font-family:Roboto}";
  // The stored (gzip) length differs from the decoded length the client receives.
  stubUpstream(encodedObjectResponse({ body: decodedCss, contentLength: "48" }));

  const response = await worker.fetch(new Request(CSS_URL), ENV);

  assert.equal(response.status, 200);
  assert.equal(await response.text(), decodedCss);
  assert.equal(response.headers.get("content-length"), String(decodedCss.length));
  assert.equal(response.headers.get("content-encoding"), null);
  assert.equal(response.headers.get("cache-control"), "public, max-age=31536000, immutable");
  assert.equal(response.headers.get("etag"), '"abc123"');
  assert.deepEqual(mismatchWarnings(), []);
});

test("GET of a genuinely empty encoded object (content-length 0) stays a 200", async () => {
  stubUpstream(encodedObjectResponse({ body: new Uint8Array(0), contentLength: "0" }));

  const response = await worker.fetch(new Request(CSS_URL), ENV);

  assert.equal(response.status, 200);
  assert.equal(response.headers.get("content-length"), "0");
  assert.deepEqual(mismatchWarnings(), []);
});

test("GET of an encoded object that decodes past the size cap: logged 500, stream cancelled", async () => {
  let cancelled = false;
  let chunksPulled = 0;
  const oneMebibyteChunk = new Uint8Array(1024 * 1024);
  // An endless stream, like a gzip bomb: only the cap can stop the read.
  const bombStream = new ReadableStream({
    pull(controller) {
      chunksPulled += 1;
      controller.enqueue(oneMebibyteChunk);
    },
    cancel() {
      cancelled = true;
    },
  });
  stubUpstream(encodedObjectResponse({ body: bombStream, contentLength: "1000" }));

  const response = await worker.fetch(new Request(CSS_URL), ENV);

  assertUncachedMismatch500(response);
  assert.match(mismatchWarnings()[0], /reason=too-large/);
  assert.equal(cancelled, true);
  assert.ok(chunksPulled < 20, `read stopped near the cap, pulled ${chunksPulled} chunks`);
});

test("206 range of an encoded object whose decode fails: logged 500", async () => {
  stubUpstream(
    encodedObjectResponse({
      status: 206,
      body: failingBodyStream(),
      contentLength: "100",
      extraHeaders: { "content-range": "bytes 0-99/35184" },
    }),
  );

  const request = new Request(CSS_URL, { headers: { range: "bytes=0-99" } });
  const response = await worker.fetch(request, ENV);

  assertUncachedMismatch500(response);
});

test("content-encoding: identity is not treated as encoded and streams as before", async () => {
  stubUpstream(
    encodedObjectResponse({
      body: "plain",
      contentLength: "5",
      extraHeaders: { "content-encoding": "identity" },
    }),
  );

  const response = await worker.fetch(new Request(CSS_URL), ENV);

  assert.equal(response.status, 200);
  assert.equal(await response.text(), "plain");
  assert.deepEqual(mismatchWarnings(), []);
});

test("HEAD of an encoded object reads no body and keeps the stored length", async () => {
  stubUpstream(encodedObjectResponse({ body: null, contentLength: "35184" }));

  const response = await worker.fetch(new Request(CSS_URL, { method: "HEAD" }), ENV);

  assert.equal(response.status, 200);
  assert.equal(response.headers.get("content-length"), "35184");
  assert.deepEqual(mismatchWarnings(), []);
});
