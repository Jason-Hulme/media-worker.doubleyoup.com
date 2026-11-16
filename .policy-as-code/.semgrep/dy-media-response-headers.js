// Fixture for dy-media-response-headers (rule C18).

export function mediaResponse(body, { status, headers }) {
  const responseHeaders = new Headers(headers);
  responseHeaders.set("x-content-type-options", "nosniff");
  // ok: dy-media-response-headers
  return new Response(body, { status, headers: responseHeaders });
}

function notFoundThroughTheHelper(method) {
  const headers = new Headers({ "cache-control": "public, max-age=60" });
  // ok: dy-media-response-headers
  return mediaResponse(method === "HEAD" ? null : "Not found", { status: 404, headers });
}

function servedObjectThroughTheHelper(upstream) {
  const headers = new Headers({ "content-type": upstream.headers.get("content-type") });
  // ok: dy-media-response-headers
  return mediaResponse(upstream.body, { status: 200, headers });
}

function handBuiltNotFound(method) {
  const headers = new Headers({ "access-control-allow-origin": "*" });
  // ruleid: dy-media-response-headers
  return new Response(method === "HEAD" ? null : "Not found", { status: 404, headers });
}

function handBuiltObject(upstream) {
  // ruleid: dy-media-response-headers
  return new Response(upstream.body, { status: 200, headers: { "content-type": "image/svg+xml" } });
}

function handBuiltJson() {
  // ruleid: dy-media-response-headers
  return Response.json({ ok: true });
}

function handBuiltRedirect(location) {
  // ruleid: dy-media-response-headers
  return Response.redirect(location, 302);
}
