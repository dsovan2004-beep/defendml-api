export const TARGET_SECRET_REDACTION_MARKER = "[REDACTED_TARGET_SECRET]";
export const TARGET_SECRET_MIN_LENGTH = 8;

function addSensitiveValue(values, value) {
  if (typeof value !== "string" || value.length < TARGET_SECRET_MIN_LENGTH) return;
  values.add(value);
  try {
    const decoded = decodeURIComponent(value);
    if (decoded.length >= TARGET_SECRET_MIN_LENGTH) values.add(decoded);
  } catch (_) {}
}

function addUrlSensitiveValues(values, rawUrl, base) {
  if (typeof rawUrl !== "string" || !rawUrl) return;
  try {
    const parsed = base ? new URL(rawUrl, base) : new URL(rawUrl);
    addSensitiveValue(values, parsed.username);
    addSensitiveValue(values, parsed.password);
    for (const value of parsed.searchParams.values()) addSensitiveValue(values, value);
    if (parsed.hash) {
      const fragment = parsed.hash.slice(1);
      addSensitiveValue(values, fragment);
      for (const value of new URLSearchParams(fragment).values()) addSensitiveValue(values, value);
    }
  } catch (_) {}
}

export function buildTargetSensitiveValues(target) {
  const values = new Set();
  addSensitiveValue(values, target?.auth_token);
  addSensitiveValue(values, target?.api_key);
  addSensitiveValue(values, target?.protected_marker);
  if (target?.custom_headers && typeof target.custom_headers === "object") {
    for (const value of Object.values(target.custom_headers)) addSensitiveValue(values, value);
  }
  addUrlSensitiveValues(values, target?.url);
  addUrlSensitiveValues(values, target?.endpoint_path, target?.url);
  return [...values].sort((a, b) => b.length - a.length || a.localeCompare(b));
}

export function redactTargetSecrets(value, sensitiveValues) {
  if (typeof value === "string") {
    let redacted = value;
    for (const secret of sensitiveValues || []) {
      redacted = redacted.split(secret).join(TARGET_SECRET_REDACTION_MARKER);
    }
    return redacted;
  }
  if (Array.isArray(value)) return value.map((item) => redactTargetSecrets(item, sensitiveValues));
  if (value && typeof value === "object") {
    return Object.fromEntries(
      Object.entries(value).map(([key, item]) => [key, redactTargetSecrets(item, sensitiveValues)])
    );
  }
  return value;
}

export function safeTargetUrl(rawUrl) {
  try {
    const parsed = new URL(rawUrl);
    parsed.username = "";
    parsed.password = "";
    parsed.search = "";
    parsed.hash = "";
    return parsed.toString();
  } catch (_) {
    return "configured target";
  }
}

const SCAN_JOB_TRANSITIONS = Object.freeze({
  queued: Object.freeze(["running", "failed"]),
  running: Object.freeze(["queued", "completed", "failed"]),
  completed: Object.freeze([]),
  failed: Object.freeze([]),
});

export function canTransitionScanJob(from, to) {
  return Boolean(SCAN_JOB_TRANSITIONS[from]?.includes(to));
}

export function buildScanJobMessage(jobId) {
  return { jobId };
}
