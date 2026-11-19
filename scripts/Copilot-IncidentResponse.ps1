#Requires -Version 7
<#
.SYNOPSIS  Copilot data-leak response: scope -> flag external -> contain -> attribute -> guardrails -> HTML dashboard.
.NOTES     Default = READ-ONLY. Changes only happen with -Remediate, -Purge, -Harden.
.EXAMPLE   .\Copilot-IncidentResponse.ps1 -TenantAdminUrl https://contoso-admin.sharepoint.com `
              -AlertEmail soc@contoso.com -LeakPatterns "Payroll","Budget-2026" -SensitiveSites https://contoso.sharepoint.com/sites/HR
#>
[CmdletBinding()]
param(
  [Parameter(Mandatory)][string]$TenantAdminUrl,
  [Parameter(Mandatory)][string]$AlertEmail,
  [datetime]$Start = (Get-Date).AddDays(-30),
  [datetime]$End   = (Get-Date),
  [string[]]$Users,                 # limit Copilot search to these users (optional)
  [string[]]$LeakPatterns,          # file name / URL fragments identifying the leaked files
  [string[]]$FileUrls,              # explicit file URLs (use for testing without Copilot data)
  [string[]]$SensitiveSites,        # site URLs to lock down (Restricted Content Discovery)
  [string]$PurgeQuery,              # KQL for email/Teams copies, e.g. 'attachmentnames:"Payroll.xlsx" AND sent>=2026-11-01'
  [string]$OutDir = ".\CopilotIncident_$(Get-Date -f yyyyMMdd_HHmm)",
  [switch]$Remediate,               # remove risky permissions/links on leaked files
  [switch]$Purge,                   # soft-delete mail/Teams copies matched by -PurgeQuery
  [switch]$Harden                   # apply tenant guardrails (sharing defaults, alerts, RCD)
)
$ErrorActionPreference = 'Continue'
New-Item $OutDir -ItemType Directory -Force | Out-Null

# ---------- Connect (Graph FIRST: avoids MSAL assembly conflict with ExchangeOnline) ----------
try {
  Import-Module Microsoft.Graph.Authentication -ErrorAction Stop
  Import-Module Microsoft.Graph.Identity.SignIns -ErrorAction Stop
  Connect-MgGraph -Scopes Files.ReadWrite.All, Sites.FullControl.All, Policy.Read.All -NoWelcome
} catch { Write-Warning "Graph unavailable ($($_.Exception.Message)). Permission scan/CA check will fail. Try a fresh pwsh window or Update-Module Microsoft.Graph*" }
if ((Get-Command Import-Module).Parameters.ContainsKey('UseWindowsPowerShell')) {
  Import-Module Microsoft.Online.SharePoint.PowerShell -UseWindowsPowerShell -WarningAction SilentlyContinue
} else { Import-Module Microsoft.Online.SharePoint.PowerShell -DisableNameChecking -WarningAction SilentlyContinue }
Connect-SPOService -Url $TenantAdminUrl
Connect-ExchangeOnline -ShowBanner:$false
Connect-IPPSSession -ShowBanner:$false
$ual = (Get-AdminAuditLogConfig).UnifiedAuditLogIngestionEnabled
if (-not $ual) { Write-Warning "Unified audit log is OFF. Enable: Set-AdminAuditLogConfig -UnifiedAuditLogIngestionEnabled `$true (takes time to start; no history is recorded while off)." }
$script:auditFailed = $false
$Internal = (Get-AcceptedDomain).DomainName

# ---------- Helpers ----------
function Esc($s) { [Net.WebUtility]::HtmlEncode([string]$s) }
function Get-Audit {
  param($Ops, $Rec, [switch]$AllUsers)
  $base = @{StartDate=$Start; EndDate=$End; ResultSize=5000}
  if ($Ops) { $base.Operations = $Ops }
  if ($Rec) { $base.RecordType = $Rec }
  if ($Users -and -not $AllUsers) { $base.UserIds = $Users }
  $out = @()
  try {
    $sid = [guid]::NewGuid().ToString()
    do {
      $b = Search-UnifiedAuditLog @base -SessionId $sid -SessionCommand ReturnLargeSet -ErrorAction Stop -WarningVariable wv -WarningAction SilentlyContinue
      if ($wv) { Write-Warning ($wv -join '; '); $script:auditFailed = $true; break }
      $out += $b
    } while ($b.Count -gt 0)
  } catch {
    Write-Warning "Audit search failed: $($_.Exception.Message)"; $script:auditFailed = $true
  }
  $out | Sort-Object Identity -Unique
}
function IsExt($addr) { $addr -match '#EXT#' -or ($addr -match '@' -and $addr.Split('@')[-1] -notin $Internal) }
function Get-Exposure($op, $d, $actor) {
  if ($op -eq 'AnonymousLinkCreated') { return 'Anonymous' }
  $t = "$($d.TargetUserOrGroupName)"
  if ($d.TargetUserOrGroupType -eq 'Guest' -or (IsExt $t)) { return 'External' }
  if (IsExt $actor) { return 'External actor' }
  if ($op -eq 'CompanyLinkCreated') { return 'Org-wide' }
  'Internal'
}
$checks = [System.Collections.Generic.List[object]]::new()
function Add-Check($Pillar, $Check, $Status, $Detail, $Fix = '') {
  $checks.Add([pscustomobject]@{Pillar=$Pillar; Check=$Check; Status=$Status; Detail=$Detail; Fix=$Fix})
}

# ---------- 1. Copilot audit: what did Copilot touch? ----------
Write-Host "[1/7] Copilot interactions..." -ForegroundColor Cyan
$all = Get-Audit -Rec CopilotInteraction
$rows = foreach ($e in $all) {
  $d = $e.AuditData | ConvertFrom-Json
  foreach ($r in $d.CopilotEventData.AccessedResources) {
    [pscustomobject]@{ Time=$e.CreationDate; User=$e.UserIds; App=$d.CopilotEventData.AppHost
      Name=$r.Name; Url=$(if ($r.ID -like 'http*') { $r.ID } else { $r.SiteUrl }); Type=$r.Type; Label=$r.SensitivityLabelId }
  }
}
if ($LeakPatterns) { $rows = $rows | Where-Object { $r = $_; $LeakPatterns | Where-Object { "$($r.Name) $($r.Url)" -like "*$_*" } } }
$rows | Export-Csv "$OutDir\copilot_resources.csv" -NoTypeInformation

# ---------- 2. Sharing / download events with EXTERNAL flag ----------
Write-Host "[2/7] Sharing + exfil events (external flagging)..." -ForegroundColor Cyan
$urlSet = [Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
$rows | Where-Object { $_.Url -like 'http*' } | ForEach-Object { [void]$urlSet.Add([uri]::UnescapeDataString($_.Url)) }
foreach ($u in $FileUrls) { [void]$urlSet.Add([uri]::UnescapeDataString($u)) }
$ops = 'SharingSet','AnonymousLinkCreated','CompanyLinkCreated','SecureLinkCreated','SharingInvitationCreated',
       'AddedToSecureLink','FileDownloaded','FileCopied','FileAccessedExtended','FileSyncDownloadedFull'
$ev = foreach ($e in (Get-Audit -Ops $ops -AllUsers)) {
  $d = $e.AuditData | ConvertFrom-Json
  $obj = [uri]::UnescapeDataString("$($d.ObjectId)")
  if (-not $urlSet.Contains($obj)) { continue }          # exact URL match; loosen if your URLs differ
  [pscustomobject]@{ Time=$e.CreationDate; User=$e.UserIds; Operation=$e.Operations; File=$obj
    Target=$d.TargetUserOrGroupName; Exposure=(Get-Exposure $e.Operations $d $e.UserIds); IP=$d.ClientIP }
} 
$ev = @($ev | Sort-Object Time)
$ev | Export-Csv "$OutDir\sharing_events.csv" -NoTypeInformation
$extEv = @($ev | Where-Object { $_.Exposure -in 'External','Anonymous','External actor' })

# ---------- 3. Email path (external recipients) ----------
Write-Host "[3/7] Message trace (last 10 days, external recipients)..." -ForegroundColor Cyan
$mailUsers = if ($Users) { $Users } else { $all.UserIds | Sort-Object -Unique | Select-Object -First 50 }
$mt = foreach ($u in $mailUsers) {
  try {
    Get-MessageTraceV2 -StartDate ([datetime]::UtcNow.AddDays(-10)) -EndDate ([datetime]::UtcNow) -SenderAddress $u |
      Where-Object { $_.RecipientAddress.Split('@')[-1] -notin $Internal } |
      Select-Object Received, SenderAddress, RecipientAddress, Subject, Status
  } catch { Write-Warning "Trace failed for $u : $($_.Exception.Message)" }
}
$mt | Export-Csv "$OutDir\external_mail.csv" -NoTypeInformation

# ---------- 4. Permission scan + recall (SharePoint / OneDrive / Teams files) ----------
Write-Host "[4/7] Permissions on leaked files (Remediate=$Remediate)..." -ForegroundColor Cyan
function ShareId($u) { 'u!' + [Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes($u)).TrimEnd('=').Replace('/','_').Replace('+','-') }
$perm = foreach ($url in $urlSet) {
  try {
    $it = Invoke-MgGraphRequest GET "v1.0/shares/$(ShareId $url)/driveItem"
    $ps = (Invoke-MgGraphRequest GET "v1.0/drives/$($it.parentReference.driveId)/items/$($it.id)/permissions").value
  } catch { [pscustomobject]@{File=$url; LinkScope=''; Who=''; Roles=''; Risky=$false; Inherited=$false; Action="ERR: $($_.Exception.Message)"}; continue }
  foreach ($p in $ps) {
    $scope = $p.link.scope
    $who = @($p.grantedToV2.user.email; $p.grantedToV2.siteUser.loginName; $p.grantedToIdentitiesV2.user.email) | Where-Object { $_ }
    $risky = ($scope -in 'anonymous','organization') -or [bool]($who | Where-Object { IsExt $_ })
    $inh = [bool]$p.inheritedFrom; $act = 'none'
    if ($risky -and -not $inh) {
      if ($Remediate) {
        try { Invoke-MgGraphRequest DELETE "v1.0/drives/$($it.parentReference.driveId)/items/$($it.id)/permissions/$($p.id)"; $act = 'REMOVED' }
        catch { $act = "FAILED: $($_.Exception.Message)" }
      } else { $act = 'would remove' }
    } elseif ($risky) { $act = 'INHERITED - fix at site/library' }
    [pscustomobject]@{File=$url; LinkScope=$scope; Who=($who -join ';'); Roles=($p.roles -join ','); Risky=$risky; Inherited=$inh; Action=$act}
  }
}
$perm | Export-Csv "$OutDir\permissions.csv" -NoTypeInformation
$riskyPerm = @($perm | Where-Object Risky)

# ---------- 5. Purge email / Teams copies ----------
Write-Host "[5/7] Mail/Teams search..." -ForegroundColor Cyan
if ($PurgeQuery) {
  $n = "INC-Copilot-$(Get-Date -f MMddHHmm)"
  New-ComplianceSearch -Name $n -ExchangeLocation All -ContentMatchQuery $PurgeQuery | Out-Null
  Start-ComplianceSearch -Identity $n
  do { Start-Sleep 15; $cs = Get-ComplianceSearch -Identity $n } until ($cs.Status -eq 'Completed')
  $msg = "$($cs.Items) items matched in search $n"
  if ($Purge) {
    New-ComplianceSearchAction -SearchName $n -Purge -PurgeType SoftDelete -Confirm:$false | Out-Null
    Add-Check 'Containment' 'Mail/Teams purge' 'Pass' "$msg; SoftDelete submitted (~10 items/mailbox/run, repeat if needed)"
  } else { Add-Check 'Containment' 'Mail/Teams purge' 'Warn' "$msg; NOT purged (use -Purge)" 'Review search results, export evidence, re-run with -Purge' }
} else { Add-Check 'Containment' 'Mail/Teams purge' 'Manual' 'No -PurgeQuery supplied' 'Supply KQL for the leaked attachment/subject' }
$ext1 = @($extEv).Count
$blind = (-not $ual) -or $script:auditFailed
Add-Check 'Containment' 'Copilot interaction records found' $(if ($all.Count -gt 0) {'Pass'} else {'Warn'}) "$($all.Count) CopilotInteraction events" 'None found: no Copilot licence/usage, audit off, or search failed'
Add-Check 'Containment' 'External exposure of leaked files' $(if ($blind) {'Warn'} elseif ($ext1 -eq 0) {'Pass'} else {'Fail'}) $(if ($blind) {'NO AUDIT DATA (audit off or search failed) - result unreliable'} else {"$ext1 external/anonymous events in audit"}) 'Review sharing_events.csv; contact recipients in writing'
Add-Check 'Containment' 'Risky permissions on leaked files' $(if ($riskyPerm.Count -eq 0) {'Pass'} elseif ($Remediate) {'Warn'} else {'Fail'}) "$($riskyPerm.Count) risky permissions ($(@($riskyPerm|Where-Object Action -eq 'REMOVED').Count) removed)" 'Run with -Remediate; fix inherited ones at site level'
Add-Check 'Containment' 'External email with leaked subjects' $(if (@($mt).Count -eq 0) {'Pass'} else {'Warn'}) "$(@($mt).Count) external messages from involved users (10-day trace)" 'Review external_mail.csv; attachments are not visible in trace'

# ---------- 6. Guardrails: assess (and apply with -Harden) ----------
Write-Host "[6/7] Guardrails (Harden=$Harden)..." -ForegroundColor Cyan
Add-Check 'Monitoring' 'Unified audit log enabled' $(if ($ual) {'Pass'} else {'Fail'}) "Ingestion=$ual" 'Set-AdminAuditLogConfig -UnifiedAuditLogIngestionEnabled $true'

$t = Get-SPOTenant
$ok = $t.DefaultSharingLinkType -eq 'Direct'
if (-not $ok -and $Harden) { Set-SPOTenant -DefaultSharingLinkType Direct; $ok = $true; $dt = 'Set to Direct by script' } else { $dt = "Current: $($t.DefaultSharingLinkType)" }
Add-Check 'Sharing' 'Default link = Specific people' $(if ($ok) {'Pass'} else {'Fail'}) $dt 'Set-SPOTenant -DefaultSharingLinkType Direct'

$anyone = $t.SharingCapability -eq 'ExternalUserAndGuestSharing'
if ($anyone -and $Harden) { Set-SPOTenant -SharingCapability ExternalUserSharingOnly; $anyone = $false; $dt = 'Anyone links disabled by script' } else { $dt = "SharingCapability: $($t.SharingCapability)" }
Add-Check 'Sharing' 'Anyone links disabled' $(if ($anyone) {'Fail'} else {'Pass'}) $dt 'Set-SPOTenant -SharingCapability ExternalUserSharingOnly'
if ($anyone) {
  $exp = $t.RequireAnonymousLinksExpireInDays
  Add-Check 'Sharing' 'Anyone-link expiry' $(if ($exp -gt 0 -and $exp -le 30) {'Pass'} else {'Fail'}) "Expiry days: $exp" 'Set-SPOTenant -RequireAnonymousLinksExpireInDays 7'
}

foreach ($s in $SensitiveSites) {
  try {
    $site = Get-SPOSite -Identity $s
    $rcd = [bool]$site.RestrictContentOrgWideSearch
    if (-not $rcd -and $Harden) { Set-SPOSite -Identity $s -RestrictContentOrgWideSearch $true; $rcd = $true }
    Add-Check 'Copilot scope' "Restricted Content Discovery: $s" $(if ($rcd) {'Pass'} else {'Fail'}) "Enabled=$rcd" 'Set-SPOSite -Identity <url> -RestrictContentOrgWideSearch $true'
  } catch { Add-Check 'Copilot scope' "Restricted Content Discovery: $s" 'Warn' $_.Exception.Message }
}
try {  # Data access governance snapshot (SharePoint Advanced Management)
  if ($Harden) {
    Start-SPODataAccessGovernanceInsight -ReportEntity EveryoneExceptExternalUsersAtSite -Workload SharePoint -ReportType Snapshot -Name "INC-EEEU-$(Get-Date -f yyyyMMdd)" -CountOfUsersMoreThan 0 | Out-Null
    Add-Check 'Copilot scope' '"Everyone except external users" report' 'Pass' 'Snapshot started; view in SharePoint admin > Reports > Data access governance'
  } else { Add-Check 'Copilot scope' '"Everyone except external users" report' 'Manual' 'Not run' 'Re-run with -Harden or run in SPO admin > Data access governance' }
} catch { Add-Check 'Copilot scope' '"Everyone except external users" report' 'Warn' "Needs SharePoint Advanced Management: $($_.Exception.Message)" }

$labels = @(Get-Label -ErrorAction SilentlyContinue).Count
Add-Check 'Labels' 'Sensitivity labels published' $(if ($labels -gt 0) {'Pass'} else {'Fail'}) "$labels labels" 'Purview > Information protection > Labels'
$auto = @(Get-AutoSensitivityLabelPolicy -ErrorAction SilentlyContinue).Count
Add-Check 'Labels' 'Auto-labeling policies' $(if ($auto -gt 0) {'Pass'} else {'Fail'}) "$auto policies" 'Create auto-labeling for PII/financial SITs with encryption (portal)'
$dlp = @(Get-DlpCompliancePolicy -ErrorAction SilentlyContinue).Count
Add-Check 'DLP' 'DLP policies exist' $(if ($dlp -gt 0) {'Pass'} else {'Fail'}) "$dlp policies" 'Purview > DLP'
Add-Check 'DLP' 'DLP policy scoped to Microsoft 365 Copilot location' 'Manual' 'Cannot be reliably verified via PowerShell' 'Purview > DLP > Policies > check Copilot location is selected'
$ret = @(Get-RetentionCompliancePolicy -ErrorAction SilentlyContinue).Count
Add-Check 'Monitoring' 'Retention policy for Copilot interactions' 'Manual' "$ret retention policies; Copilot location not verifiable in PS" 'Purview > Data lifecycle > Retention > Copilot experiences'

foreach ($a in @(
  @{N='INC - Anonymous link created'; Op='AnonymousLinkCreated'; Agg='None'; Thr=$null},
  @{N='INC - Mass file download';     Op='FileDownloaded';       Agg='SimpleAggregation'; Thr=100})) {
  $exists = Get-ProtectionAlert -Identity $a.N -ErrorAction SilentlyContinue
  if (-not $exists -and $Harden) {
    $p = @{Name=$a.N; Category='Others'; ThreatType='Activity'; Operation=$a.Op; NotifyUser=$AlertEmail; Severity='High'
           AggregationType=$a.Agg; Description='Created by Copilot incident script'}
    if ($a.Thr) { $p.Threshold = $a.Thr; $p.TimeWindow = 60 }
    try { New-ProtectionAlert @p | Out-Null; $exists = $true } catch { Add-Check 'Monitoring' $a.N 'Warn' $_.Exception.Message; continue }
  }
  Add-Check 'Monitoring' "Alert policy: $($a.N)" $(if ($exists) {'Pass'} else {'Fail'}) $(if ($exists) {'Present'} else {'Missing'}) 'Run with -Harden'
}

try {
  $ca = @(Get-MgIdentityConditionalAccessPolicy -All | Where-Object State -eq 'enabled')
  $mfa = @($ca | Where-Object { $_.GrantControls.BuiltInControls -match 'mfa|compliantDevice' }).Count
  Add-Check 'Identity' 'Conditional Access (MFA/compliant device)' $(if ($mfa -gt 0) {'Pass'} else {'Fail'}) "$($ca.Count) enabled policies, $mfa require MFA/compliant device" 'Entra > Conditional Access (create in report-only first)'
} catch { Add-Check 'Identity' 'Conditional Access' 'Warn' $_.Exception.Message }

foreach ($m in @(
  @('DSPM for AI','Purview > DSPM for AI: enable one-click policies and run oversharing assessment'),
  @('Insider Risk "Risky AI usage" policy','Purview > Insider Risk Management'),
  @('Communication Compliance for Copilot prompts','Purview > Communication Compliance'),
  @('Site access reviews (SAM)','SharePoint admin > Data access governance > Site access review'),
  @('Restricted Access Control on sensitive sites','Set-SPOSite -RestrictedAccessControl needs a security group per site'),
  @('Phased Copilot licensing by group','Assign Copilot licences only after oversharing review'))) {
  Add-Check 'Portal-only' $m[0] 'Manual' 'No supported scripting path' $m[1]
}
$checks | Export-Csv "$OutDir\guardrail_checks.csv" -NoTypeInformation

# ---------- 7. Dashboard ----------
Write-Host "[7/7] Building dashboard..." -ForegroundColor Cyan
function Tbl($data, $cols, $cls) {
  $data = @($data | Where-Object { $_ }); if (-not $data.Count) { return '<p class="muted">No data</p>' }
  $h = '<div class="scroll"><table><tr>' + (($cols | ForEach-Object { "<th>$_</th>" }) -join '') + '</tr>'
  foreach ($r in ($data | Select-Object -First 300)) {
    $c = if ($cls) { "class='$(($r.$cls) -replace '\W','')'" }
    $h += "<tr $c>" + (($cols | ForEach-Object { "<td>$(Esc $r.$_)</td>" }) -join '') + '</tr>'
  }
  $h + '</table></div>'
}
function Card($label, $val, $cls = '') { "<div class='card $cls'><div class='v'>$val</div><div class='l'>$label</div></div>" }
function Bars($pairs) {
  $pairs = @($pairs | Where-Object { $_ }); if (-not $pairs.Count) { return '<p class="muted">No data</p>' }
  $max = [math]::Max(1, [int]($pairs | Measure-Object Count -Maximum).Maximum)
  ($pairs | ForEach-Object { "<div class='bar'><span class='bl'>$(Esc $_.Name)</span><span class='bb'><i style='width:$([math]::Round(100*$_.Count/$max))%'></i></span><span class='bn'>$($_.Count)</span></div>" }) -join ''
}
$cnt = @{}; foreach ($s in 'Pass','Fail','Warn','Manual') { $cnt[$s] = @($checks | Where-Object Status -eq $s).Count }
$tot = [math]::Max(1, $checks.Count)
$p1 = [math]::Round(100*$cnt.Pass/$tot); $p2 = $p1 + [math]::Round(100*$cnt.Fail/$tot); $p3 = $p2 + [math]::Round(100*$cnt.Warn/$tot)
$donut = "conic-gradient(#107c10 0 $p1%, #d13438 $p1% $p2%, #f7a900 $p2% $p3%, #8a8886 $p3% 100%)"

$culprits = $ev | Group-Object User | ForEach-Object {
  $g = $_.Group
  $x = @($g | Where-Object { $_.Exposure -in 'External','Anonymous','External actor' }).Count
  $o = @($g | Where-Object Exposure -eq 'Org-wide').Count
  $dl = @($g | Where-Object { $_.Operation -in 'FileDownloaded','FileCopied','FileSyncDownloadedFull' }).Count
  [pscustomobject]@{ User=$_.Name; ExternalShares=$x; OrgWideLinks=$o; Downloads=$dl
    CopilotPrompts=@($all | Where-Object UserIds -eq $_.Name).Count; Score=(3*$x + $o + $dl) }
} | Sort-Object Score -Descending
$topUsers = $all | Group-Object UserIds | Sort-Object Count -Descending | Select-Object -First 10 | ForEach-Object { [pscustomobject]@{Name=$_.Name; Count=$_.Count} }
$daily = $all | Group-Object { $_.CreationDate.ToString('MM-dd') } | Sort-Object Name | ForEach-Object { [pscustomobject]@{Name=$_.Name; Count=$_.Count} }
$expo = $ev | Group-Object Exposure | ForEach-Object { [pscustomobject]@{Name=$_.Name; Count=$_.Count} }
$pillars = $checks | Group-Object Pillar | ForEach-Object {
  $g = $_.Group; "<div class='pill'><b>$(Esc $_.Name)</b><span class='ok'>$(@($g|Where-Object Status -eq 'Pass').Count) pass</span> <span class='bad'>$(@($g|Where-Object Status -eq 'Fail').Count) fail</span> <span class='wrn'>$(@($g|Where-Object Status -eq 'Warn').Count) warn</span> <span class='man'>$(@($g|Where-Object Status -eq 'Manual').Count) manual</span></div>" }

$html = @"
<!DOCTYPE html><html><head><meta charset="utf-8"><title>Copilot Incident Report</title>
<style>
body{font-family:Segoe UI,Arial,sans-serif;margin:0;background:#f3f2f1;color:#201f1e}
header{background:#0f4c81;color:#fff;padding:22px 32px}header h1{margin:0;font-size:22px}header p{margin:4px 0 0;opacity:.85;font-size:13px}
main{padding:20px 32px;max-width:1400px;margin:auto}h2{font-size:16px;margin:26px 0 10px;border-left:4px solid #0f4c81;padding-left:10px}
.cards{display:grid;grid-template-columns:repeat(auto-fit,minmax(170px,1fr));gap:12px}
.card{background:#fff;border-radius:6px;padding:14px 16px;box-shadow:0 1px 3px #0002;border-top:4px solid #0f4c81}
.card.red{border-top-color:#d13438}.card.amber{border-top-color:#f7a900}.card.green{border-top-color:#107c10}
.v{font-size:30px;font-weight:600}.l{font-size:12px;color:#605e5c;margin-top:2px}
.grid{display:grid;grid-template-columns:1fr 1fr;gap:16px}@media(max-width:900px){.grid{grid-template-columns:1fr}}
.panel{background:#fff;border-radius:6px;padding:14px 16px;box-shadow:0 1px 3px #0002}
.donutwrap{display:flex;align-items:center;gap:24px}.donut{width:130px;height:130px;border-radius:50%;background:$donut;position:relative;flex:none}
.donut:after{content:"$p1%";position:absolute;inset:26px;background:#fff;border-radius:50%;display:flex;align-items:center;justify-content:center;font-weight:600;font-size:20px}
.legend span{display:block;font-size:13px;margin:3px 0}.legend i{display:inline-block;width:10px;height:10px;border-radius:2px;margin-right:6px}
.pill{display:flex;gap:10px;align-items:center;padding:6px 0;border-bottom:1px solid #edebe9;font-size:13px}.pill b{min-width:110px}
.ok{color:#107c10}.bad{color:#d13438}.wrn{color:#b07800}.man{color:#605e5c}
.scroll{overflow-x:auto;max-height:480px;overflow-y:auto}table{border-collapse:collapse;width:100%;font-size:12.5px}
th{background:#faf9f8;text-align:left;position:sticky;top:0;padding:7px 8px;border-bottom:2px solid #edebe9}td{padding:6px 8px;border-bottom:1px solid #edebe9;vertical-align:top;word-break:break-word}
tr.Fail td:first-child,tr.External td,tr.Anonymous td,tr.Externalactor td{background:#fde7e9}tr.Warn td:first-child{background:#fff4ce}tr.Pass td:first-child{background:#dff6dd}tr.Orgwide td{background:#fff4ce}
.bar{display:flex;align-items:center;gap:8px;font-size:12px;margin:4px 0}.bl{width:170px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}.bb{flex:1;background:#edebe9;height:12px;border-radius:3px}.bb i{display:block;height:12px;background:#0f4c81;border-radius:3px}.bn{width:34px;text-align:right}
.muted{color:#605e5c;font-size:13px}
</style></head><body>
<header><h1>Microsoft 365 Copilot - Data Exposure Incident Report</h1>
<p>Window: $($Start.ToString('yyyy-MM-dd')) to $($End.ToString('yyyy-MM-dd')) &nbsp;|&nbsp; Generated: $(Get-Date -f 'yyyy-MM-dd HH:mm') &nbsp;|&nbsp; Mode: Remediate=$Remediate, Purge=$Purge, Harden=$Harden</p></header>
<main>
<div class="cards">
$(Card 'Copilot interactions' $all.Count)
$(Card 'Users prompting Copilot' @($all.UserIds | Sort-Object -Unique).Count)
$(Card 'Leaked files in scope' $urlSet.Count 'amber')
$(Card 'External / anonymous events' $extEv.Count $(if ($extEv.Count) {'red'} else {'green'}))
$(Card 'Risky permissions found' $riskyPerm.Count $(if ($riskyPerm.Count) {'red'} else {'green'}))
$(Card 'Permissions removed' @($riskyPerm | Where-Object Action -eq 'REMOVED').Count 'green')
$(Card 'External emails (10d)' @($mt).Count $(if (@($mt).Count) {'amber'} else {'green'}))
$(Card 'Guardrails failing' $cnt.Fail $(if ($cnt.Fail) {'red'} else {'green'}))
</div>

<h2>Guardrail posture</h2>
<div class="grid"><div class="panel"><div class="donutwrap"><div class="donut"></div><div class="legend">
<span><i style="background:#107c10"></i>Pass: $($cnt.Pass)</span><span><i style="background:#d13438"></i>Fail: $($cnt.Fail)</span>
<span><i style="background:#f7a900"></i>Warn: $($cnt.Warn)</span><span><i style="background:#8a8886"></i>Manual: $($cnt.Manual)</span></div></div></div>
<div class="panel">$($pillars -join '')</div></div>

<h2>Exposure and activity</h2>
<div class="grid">
<div class="panel"><b>Sharing events by exposure</b>$(Bars $expo)</div>
<div class="panel"><b>Copilot interactions per day</b>$(Bars $daily)</div>
<div class="panel"><b>Top Copilot users</b>$(Bars $topUsers)</div>
<div class="panel"><b>Culprit leaderboard</b> <span class="muted">(score = 3 x external + org-wide + downloads)</span>
$(Tbl ($culprits | Select-Object -First 15) 'User','ExternalShares','OrgWideLinks','Downloads','CopilotPrompts','Score')</div>
</div>

<h2>External / anonymous sharing events (flagged)</h2>
<div class="panel">$(Tbl ($ev | Sort-Object @{e={$_.Exposure -in 'External','Anonymous','External actor'};Descending=$true}, Time) 'Time','User','Operation','Exposure','Target','File','IP' 'Exposure')</div>

<h2>Guardrail checks</h2>
<div class="panel">$(Tbl $checks 'Status','Pillar','Check','Detail','Fix' 'Status')</div>

<h2>Permissions on leaked files</h2>
<div class="panel">$(Tbl ($perm | Sort-Object Risky -Descending) 'File','LinkScope','Who','Roles','Inherited','Action')</div>

<h2>External email from involved users (last 10 days)</h2>
<div class="panel">$(Tbl $mt 'Received','SenderAddress','RecipientAddress','Subject','Status')</div>

<h2>Copilot-accessed resources</h2>
<div class="panel">$(Tbl $rows 'Time','User','App','Name','Url','Label')</div>
</main></body></html>
"@
$report = Join-Path $OutDir 'CopilotIncidentReport.html'
$html | Out-File $report -Encoding utf8
Write-Host "Done. Report: $report" -ForegroundColor Green
Invoke-Item $report
