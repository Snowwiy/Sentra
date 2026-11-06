-- 7C-Fix2: de dónde salen las PER-001 y CORR-002 de servicios (solo lectura).
SELECT d.rule_id,
       d.rule_version,
       d.severity,
       d.confidence,
       d.status,
       d.details->>'service' AS service,
       d.details->'sources' AS sources,
       COALESCE(d.details->'classification'->>'kind',
                d.details->'persistence'->'classification'->>'kind') AS kind,
       COALESCE(d.details->'classification'->>'verification',
                d.details->'persistence'->'classification'->>'verification') AS verification,
       d.details->'causal_links' AS causal_links,
       d.occurrence_count,
       d.first_seen_at
FROM detections d
WHERE d.rule_id IN ('PER-001', 'CORR-002')
ORDER BY d.first_seen_at DESC
LIMIT 50;
