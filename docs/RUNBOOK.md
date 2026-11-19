# Incident runbook

1. **Preserve evidence.** Purview eDiscovery hold/case on affected users and sites; export current state before any deletion.
2. **Scope.** Run the script read-only. Narrow with `-LeakPatterns` / `-FileUrls`.
3. **Contain.** Review `permissions.csv`, then `-Remediate`. Fix inherited permissions at site/library level. Purge internal mail/Teams copies with `-PurgeQuery` + `-Purge`.
4. **Attribute.** Correlate Copilot prompt -> file accessed -> shared/sent using the culprit leaderboard and `sharing_events.csv`.
5. **Guardrails.** Run `-Harden`, then complete the **Manual** items in the report.
6. **Notify.** If personal data is involved, check notification duties with the customer's legal/DPO (e.g. Kenya Data Protection Act: ODPC within 72 hours of becoming aware). External recipients need a written request; recall is not possible.

## Known limitations
- Sharing events are matched to Copilot-accessed files by exact URL.
- Message trace covers 10 days and cannot see attachments.
- Purge handles roughly 10 items per mailbox per run; repeat for heavy hitters.
