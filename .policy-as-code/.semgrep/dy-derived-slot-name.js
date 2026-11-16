// Fixture for dy-derived-slot-name (rule C11).

// ok: dy-derived-slot-name
const STAGING_PREFIX_PATTERN = /^sg-(.*)$/;

// The one helper may map the prefix: the rule excludes it.
export function siteSlugFromPrefixSegment(prefixSegment) {
  // ok: dy-derived-slot-name
  const stagingMatch = STAGING_PREFIX_PATTERN.exec(prefixSegment);
  if (!stagingMatch) return prefixSegment;
  return stagingMatch[1];
}

export function handBuilt(slug, n) {
  return [
    // ruleid: dy-derived-slot-name
    `sg-${slug}`,
    // ruleid: dy-derived-slot-name
    `${slug}-staging`,
    // ruleid: dy-derived-slot-name
    `${slug}-dev${n}`,
    // ruleid: dy-derived-slot-name
    `${slug}-dev2`,
    // ruleid: dy-derived-slot-name
    slug + "-staging",
    // ruleid: dy-derived-slot-name
    slug + "-dev" + n,
    // ruleid: dy-derived-slot-name
    "sg-" + slug,
    // ruleid: dy-derived-slot-name
    'sg-' + slug,
  ];
}

export function handParsed(prefixSegment) {
  // ruleid: dy-derived-slot-name
  if (prefixSegment.startsWith("sg-")) return prefixSegment.slice(3);
  // ruleid: dy-derived-slot-name
  return prefixSegment.replace(/^sg-/, "");
}

export function throughTheHelper(prefixSegment, slug) {
  return [
    // ok: dy-derived-slot-name
    siteSlugFromPrefixSegment(prefixSegment),
    // ok: dy-derived-slot-name
    `doubleyoup-media-${slug}`,
    // ok: dy-derived-slot-name
    `${slug}/2026/11/photo.jpg`,
    // ok: dy-derived-slot-name
    "--no-staging",
    // ok: dy-derived-slot-name
    `msg-${slug}`,
  ];
}
