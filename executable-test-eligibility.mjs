// A whole-prompt redaction marker (e.g. Fix #212 inventory placeholders) is metadata, not an attack payload.
const METADATA_MARKER = /^\[REDACTED[^\]]*\]$/i;
export function isExecutableTest(test) {
  const text = typeof test?.prompt_text === 'string' ? test.prompt_text.trim() : '';
  return text.length > 0 && !METADATA_MARKER.test(text);
}
