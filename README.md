# Copilot Incident Response

One PowerShell script to respond to a **Microsoft 365 Copilot data-exposure incident**: scope what Copilot touched, flag external sharing, contain, attribute, check guardrails, and produce an HTML dashboard (Zero Trust Assessment style).

> Copilot only surfaces what a user can already access. The root cause is usually oversharing (broad links, "Everyone except external users", open Teams sites), so this tool focuses on exposure, not just prompts.

## What it does

| Phase | Output |
|---|---|
| 1. Copilot audit | Resources Copilot accessed (`copilot_resources.csv`) |
| 2. Sharing/download audit | Events per leaked file, each flagged **Anonymous / External / External actor / Org-wide / Internal** (`sharing_events.csv`) |
| 3. Email path | External recipients from involved users, 10-day trace (`external_mail.csv`) |
| 4. Permissions | Every permission on leaked files; removes risky ones with `-Remediate` (`permissions.csv`) |
| 5. Mail/Teams copies | Compliance search; soft-delete with `-Purge` |
| 6. Guardrails | Pass/Fail/Warn/Manual checks; applies fixes with `-Harden` (`guardrail_checks.csv`) |
| 7. Dashboard | `CopilotIncidentReport.html` (cards, posture donut, culprit leaderboard, flagged events) |

## Requirements

- PowerShell **7.2+** (`winget install Microsoft.PowerShell`)
- Modules: `ExchangeOnlineManagement` (3.7+), `Microsoft.Graph.Authentication`, `Microsoft.Graph.Identity.SignIns`, `Microsoft.Online.SharePoint.PowerShell`
- Roles: SharePoint Admin, Compliance/eDiscovery with **Search And Purge**, audit log access, Graph admin consent for `Files.ReadWrite.All`, `Sites.FullControl.All`, `Policy.Read.All`
- Unified audit log **enabled** (`Set-AdminAuditLogConfig -UnifiedAuditLogIngestionEnabled $true`)

## Usage

```powershell
# Safe, read-only run (default)
.\scripts\Copilot-IncidentResponse.ps1 -TenantAdminUrl https://contoso-admin.sharepoint.com `
  -AlertEmail soc@contoso.com -LeakPatterns "Payroll","Budget-2026"

# Test without Copilot data
.\scripts\Copilot-IncidentResponse.ps1 -TenantAdminUrl ... -AlertEmail ... `
  -FileUrls "https://contoso.sharepoint.com/sites/HR/Shared Documents/Test.xlsx"

# Act (review the read-only report first)
.\scripts\Copilot-IncidentResponse.ps1 ... -Remediate -Purge -PurgeQuery 'attachmentnames:"Payroll.xlsx" AND sent>=2026-11-01' -Harden
```

| Switch | Effect |
|---|---|
| *(none)* | Read-only: audit, report |
| `-Remediate` | Removes anonymous/org-wide/external permissions on leaked files |
| `-Purge` | Soft-deletes mail/Teams matches of `-PurgeQuery` |
| `-Harden` | Default link = Specific people, disable Anyone links, Restricted Content Discovery on `-SensitiveSites`, create alert policies, start "Everyone except external users" report |

## Not scriptable (shown as **Manual** in the report)
DSPM for AI, Insider Risk "Risky AI usage", Communication Compliance, site access reviews, Restricted Access Control, auto-labeling policy creation, Copilot-location DLP/retention verification.

## Safety
- **Preserve evidence first** (Purview hold/export) before `-Remediate` or `-Purge`.
- `-Harden` changes tenant-wide sharing. Get sign-off.
- Copies already delivered to external recipients **cannot be recalled**; escalate to legal.
- **Never commit output.** Reports and CSVs contain user names, file URLs and email metadata (`.gitignore` blocks them).

## Status
Early version. Tested only on a small demo tenant; not validated at scale. `New-ProtectionAlert` and audit-field parsing may need tuning per tenant. See [docs/RUNBOOK.md](docs/RUNBOOK.md). Issues and PRs welcome.

## License
MIT
