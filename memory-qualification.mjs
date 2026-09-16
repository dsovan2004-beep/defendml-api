export const MEMORY_QUALIFICATION_VERSION = 'execution-qualified-memory-v1';
export function isQualifiedMemory(row) {
  const q = row.response_patterns?.qualification;
  return q?.version === MEMORY_QUALIFICATION_VERSION && q?.state === 'QUALIFIED'
    && Number.isSafeInteger(q.qualified_outcomes) && q.qualified_outcomes > 0
    && Array.isArray(q.source_report_ids) && q.source_report_ids.length > 0
    && q.source_report_ids.every(id => typeof id === 'string' && id.length > 0);
}
export function qualifiesMemoryOutcome(row) {
  return ['BLOCK', 'ALLOW', 'FLAG'].includes(row.decision)
    && ['keyword', 'llm_judge'].includes(row.detection_method)
    && typeof row.status_code === 'number' && row.status_code >= 200 && row.status_code < 300
    && Boolean(row.response_snippet?.trim());
}
