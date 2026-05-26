#Requires -Version 7.0
#
# NLS-Assessment.psm1  (v4.5.5)
# Module loader — dot-sources all functions from Lib, Collectors, Evaluators, Publishers.
#
# Author: NextLayerSec — nextlayersec.io
#
# SECURITY HARDENING (v4.5.5):
#   - StrictMode Latest: catches uninitialized variables, property access on $null
#   - EAP Stop at module scope: dot-source failures surface immediately
#   - LiteralPath everywhere: prevents wildcard expansion on folder/file paths
#   - Path traversal check: each dot-sourced file must resolve inside $PSScriptRoot
#   - Import-PowerShellDataFile uses -LiteralPath: prevents wildcard in branding path
#   - StrictMode stays on (Set-StrictMode -Version Latest is not disabled);
#     collectors that touch potentially-null properties use null-coalescing
#     operators or explicit null checks — never a global strict-mode disable.
#
# OWASP ASVS V16.4.1 — strict mode for early error detection
# OWASP A01          — path traversal prevention on dot-sourced files
#

# Disable WAM broker before any EOM module loads
$env:MSAL_ALLOW_BROKER = '0'
$env:MSAL_DISABLE_TOKENBROKER = '1'

$ErrorActionPreference = 'Stop'

# OWASP ASVS V16.4.1 — strict mode catches uninitialized variables, property
# access on $null, and indexing past array end. Activated module-wide so every
# dot-sourced collector/evaluator/publisher runs under the same semantics. The
# Pester invariant in Testing/NLS.Security.Tests.ps1 enforces presence of this
# directive in production code going forward.
Set-StrictMode -Version Latest

$script:NLSAssessmentVersion = '4.6.4'
$script:NLSModuleRoot        = $PSScriptRoot

# Thread-safe collections for module state
$script:NLSFindings   = [System.Collections.Generic.List[object]]::new()
$script:NLSExceptions = [System.Collections.Generic.List[object]]::new()
$script:NLSCoverage   = [System.Collections.Generic.Dictionary[string,string]]::new()
$script:NLSRawData    = [System.Collections.Hashtable]::Synchronized(@{})

# ── Branding ──────────────────────────────────────────────────────────────────
# LiteralPath prevents wildcard expansion on the path.
# OWASP A01 / ASVS V12.3.1
$brandPath = Join-Path $PSScriptRoot 'Config' 'branding.psd1'
$script:NLSBrand = if (Test-Path -LiteralPath $brandPath) {
    try {
        Import-PowerShellDataFile -LiteralPath $brandPath -ErrorAction Stop
    } catch {
        Write-Warning "Branding file invalid, using defaults: $_"
        $null
    }
} else {
    $null
}

if (-not $script:NLSBrand) {
    $script:NLSBrand = @{
        CompanyName    = 'NextLayerSec'
        Phone          = '(701) 250-9400'
        Website        = 'nextlayersec.io'
        Email          = 'sales@nextlayersec.io'
        PrimaryColor   = '#1a3a6b'
        SecondaryColor = '#e87722'
        AccentColor    = '#4a7ba6'
        LogoUrl        = ''
    }
}

# ── Module file loader ────────────────────────────────────────────────────────
# Each dot-sourced file is verified to resolve inside $PSScriptRoot before loading.
# This prevents a malformed filename from causing a path traversal load.
# OWASP A01 / ASVS V12.3.1
$loadOrder = @('Lib', 'Collectors', 'Evaluators', 'Publishers')

foreach ($folder in $loadOrder) {
    $folderPath = Join-Path $PSScriptRoot $folder

    if (-not (Test-Path -LiteralPath $folderPath)) {
        Write-Warning "Module folder not found: $folder"
        continue
    }

    $files = Get-ChildItem -LiteralPath $folderPath -Filter '*.ps1' -Recurse -File -ErrorAction SilentlyContinue

    foreach ($file in $files) {
        # Verify the resolved path is inside PSScriptRoot — prevents path traversal
        # if a file is somehow named with ../ sequences (e.g. via symlink)
        $resolvedFile   = [System.IO.Path]::GetFullPath($file.FullName)
        $resolvedModule = [System.IO.Path]::GetFullPath($PSScriptRoot)

        # OWASP A01: resolved file must StartsWith $PSScriptRoot (resolved as $resolvedModule)
        if (-not $resolvedFile.StartsWith($resolvedModule, [StringComparison]::OrdinalIgnoreCase)) {
            Write-Warning "Skipping file outside module root (path traversal?): $($file.FullName)"
            continue
        }

        try {
            # Redirect information stream (3>) to suppress verbose module load noise
            . $file.FullName 3>$null
        } catch {
            $loadMsg = "Failed to load $($file.Name): $($_.Exception.Message)"
            Write-Warning $loadMsg
            # v4.6.3 P2: surface load failures into the run's exception list so
            # Get-NLSExceptions / the JSON output includes them. Without this,
            # a dot-source failure was a Write-Warning only — operators only
            # noticed if they were watching the console. Note Register-NLSException
            # may not exist yet if Add-NLSFinding.ps1 was the file that failed —
            # guard with Get-Command.
            if (Get-Command Register-NLSException -ErrorAction SilentlyContinue) {
                try { Register-NLSException -Source 'ModuleLoader' -Message $loadMsg } catch { }
            }
        }
    }
}

# ── Exported function list ────────────────────────────────────────────────────
$script:ExportedFunctions = @(
    # ── Lib helpers ───────────────────────────────────────────────────────────
    'Add-NLSFinding', 'Get-NLSFindings', 'Clear-NLSFindings', 'Clear-NLSState',
    'Register-NLSException', 'Get-NLSExceptions',
    'Register-NLSCoverage', 'Get-NLSCoverage',
    'Set-NLSRawData', 'Get-NLSRawData',
    'Connect-NLSServices', 'Disconnect-NLSServices',
    'ConvertTo-NLSHtmlSafe', 'ConvertTo-NLSSafeUrl',
    'Get-NLSControlDefinitions', 'Get-NLSControlById',
    'Get-NLSFrameworkCitations', 'Get-NLSFrameworkDefinitions',
    'Get-NLSFindingRiskCost', 'Get-NLSAggregateRisk',
    'Set-NLSSensitiveFileAcl', 'Set-NLSSensitiveFileContent',
    'Get-NLSTenantLicenseProfile', 'Test-NLSLicenseRequirementMet',
    'Get-NLSSafeProperty', 'Get-NLSNestedProperty',

    # ── Collectors — AAD ──────────────────────────────────────────────────────
    'Invoke-NLSCollectAADAuthPolicies', 'Invoke-NLSCollectAADCAPolicies',
    'Invoke-NLSCollectAADUsers', 'Invoke-NLSCollectAADRoles',
    'Invoke-NLSCollectAADPIM', 'Invoke-NLSCollectAADIdentityGovernance',
    'Invoke-NLSCollectAADInventory',

    # ── Collectors — EXO / Defender / DNS ─────────────────────────────────────
    'Invoke-NLSCollectEXOMailboxConfig', 'Invoke-NLSCollectEXOConnectionFilter',
    'Invoke-NLSCollectEXOInventory',
    'Invoke-NLSCollectDefender', 'Invoke-NLSCollectDNSEmailRecords',

    # ── Collectors — Phase 2+ ─────────────────────────────────────────────────
    'Invoke-NLSCollectSharePoint', 'Invoke-NLSCollectTeams',
    'Invoke-NLSCollectPurview',
    'Invoke-NLSCollectIntuneEndpointSecurity',
    'Invoke-NLSCollectIntuneDeviceCompliance',
    'Invoke-NLSCollectIntuneAppProtection',
    'Invoke-NLSCollectPowerPlatform',
    'Invoke-NLSCollectM365Copilot',

    # ── Evaluators — AAD ──────────────────────────────────────────────────────
    'Test-NLSControlAADLegacyAuth', 'Test-NLSControlAADMFA',
    'Test-NLSControlAADPhishResistantMFA', 'Test-NLSControlAADCA',
    'Test-NLSControlAADPrivAccess', 'Test-NLSControlAADSignInRisk',
    'Test-NLSControlAADUserRisk', 'Test-NLSControlAADNamedLocations',
    'Test-NLSControlAADDeviceComplianceCA', 'Test-NLSControlAADNoPermanentAdmins',
    'Test-NLSControlAADPIMMFA', 'Test-NLSControlAADPIMJustification',
    'Test-NLSControlAADPIMApproval', 'Test-NLSControlAADPIMDuration',
    'Test-NLSControlAADGuestInvite', 'Test-NLSControlAADExternalCollab',
    'Test-NLSControlAADGuestPermissions', 'Test-NLSControlAADSSPR',
    'Test-NLSControlAADSSPRMethods', 'Test-NLSControlAADUserAppReg',
    'Test-NLSControlAADUserConsent', 'Test-NLSControlAADAdminConsentWorkflow',
    'Test-NLSControlAADPasswordProtection', 'Test-NLSControlAADBreakGlass',
    'Test-NLSControlAADPIMAlerts', 'Test-NLSControlAADAccessReviews',
    'Test-NLSControlAADAuthenticatorNumberMatch', 'Test-NLSControlAADPasswordless',
    'Test-NLSControlAADIdentityProtection', 'Test-NLSControlAADPrivCloudOnly',
    'Test-NLSControlAADBreakGlassMonitoring', 'Test-NLSControlAADSignInFrequency',
    'Test-NLSControlAADDeviceCode', 'Test-NLSControlAADNoGuestInPrivRoles',
    'Test-NLSControlAADRiskyServicePrincipals', 'Test-NLSControlAADTokenProtection',
    'Test-NLSControlAADContinuousAccess', 'Test-NLSControlAADCrossTenantAccess',
    'Test-NLSControlAADPrivilegedWorkstation', 'Test-NLSControlAADTermsOfUse',
    'Test-NLSControlAADWorkloadIdentityCA',

    # ── Evaluators — DNS ──────────────────────────────────────────────────────
    'Test-NLSControlDNSSPF', 'Test-NLSControlDNSDKIM', 'Test-NLSControlDNSDMARC',
    'Test-NLSControlDNSMTASTS', 'Test-NLSControlDNSTLSRPT', 'Test-NLSControlDNSDNSSEC',
    'Test-NLSControlDNSDkimRotation', 'Test-NLSControlDNSCAA',
    'Test-NLSControlDNSTLSCertExpiry', 'Test-NLSControlDNSCertTransparency',

    # ── Evaluators — EXO ──────────────────────────────────────────────────────
    'Test-NLSControlEXOMailboxAudit', 'Test-NLSControlEXOSmtpAuth',
    'Test-NLSControlEXOAutoForward', 'Test-NLSControlEXODKIM',
    'Test-NLSControlEXOAntiPhish', 'Test-NLSControlEXOModernAuth',
    'Test-NLSControlEXOHonorDMARC', 'Test-NLSControlEXOPop3',
    'Test-NLSControlEXOImap', 'Test-NLSControlEXOCustomerLockbox',
    'Test-NLSControlEXOSharedMailbox', 'Test-NLSControlEXOConnectionFilter',
    'Test-NLSControlEXOOutboundLimits', 'Test-NLSControlEXOAlertForwarding',
    'Test-NLSControlEXOAlertVolume', 'Test-NLSControlEXOTransportAudit',
    'Test-NLSControlEXOAuditAgeLimit', 'Test-NLSControlEXOAdminAudit',
    'Test-NLSControlEXOSafeAttachmentsSPO', 'Test-NLSControlEXOAntiSpamInbound',
    'Test-NLSControlEXOPerUserAudit', 'Test-NLSControlEXOPriorityAccountProtection',
    'Test-NLSControlEXOSafeSenderOverride',
    'Test-NLSControlEXOMailboxForwarding', 'Test-NLSControlEXOInboxRulesForwarding',
    'Test-NLSControlEXOAuditDisabledMailboxes', 'Test-NLSControlEXOSmtpAuthExceptions',

    # ── Evaluators — Defender ─────────────────────────────────────────────────
    'Test-NLSControlDefender',
    'Test-NLSControlDefenderPresetPolicies', 'Test-NLSControlDefenderZAP',
    'Test-NLSControlDefenderCommonAttachments', 'Test-NLSControlDefenderQuarantine',
    'Test-NLSControlDefenderHCSpam', 'Test-NLSControlDefenderBulkThreshold',
    'Test-NLSControlDefenderUnauthSender', 'Test-NLSControlDefenderViaTag',
    'Test-NLSControlDefenderMDCA', 'Test-NLSControlDefenderAlertNotification',
    'Test-NLSControlDefenderDLPWorkloads', 'Test-NLSControlDefenderDLPSITs',
    'Test-NLSControlDefenderRiskyAppAlerts', 'Test-NLSControlDefenderPriorityAccounts',
    'Test-NLSControlDefenderEndpointDLP', 'Test-NLSControlDefenderAttackSim',
    'Test-NLSControlDefenderSafeLinksOffice',

    # ── Evaluators — SharePoint ───────────────────────────────────────────────
    'Test-NLSControlSharePoint',
    'Test-NLSControlSPOOneDriveSync', 'Test-NLSControlSPOLinkExpiration',
    'Test-NLSControlSPOAppsFromStore', 'Test-NLSControlSPOCustomScript',
    'Test-NLSControlSPO3PStorage', 'Test-NLSControlSPOEmailAttestation',
    'Test-NLSControlSPOReauth', 'Test-NLSControlSPODomainSync',
    'Test-NLSControlSPOSiteAdmins', 'Test-NLSControlSPOSharingNotifications',
    'Test-NLSControlSPOVersionHistory', 'Test-NLSControlSPOGuestExpiry',

    # ── Evaluators — Teams ────────────────────────────────────────────────────
    'Test-NLSControlTeams',
    'Test-NLSControlTeamsSkype', 'Test-NLSControlTeamsUnverifiedApps',
    'Test-NLSControlTeams3PStorage', 'Test-NLSControlTeamsEmailIntegration',
    'Test-NLSControlTeamsRecordingExternal', 'Test-NLSControlTeamsBroadChannel',
    'Test-NLSControlTeamsExternalChat', 'Test-NLSControlTeamsPSTN',
    'Test-NLSControlTeamsWatermarks', 'Test-NLSControlTeamsAutoAdmit',
    'Test-NLSControlTeamsMeetingChat', 'Test-NLSControlTeamsChatCopy',
    'Test-NLSControlTeamsMeetingRecordingScope', 'Test-NLSControlTeamsAnonymousStart',
    'Test-NLSControlTeamsFederationAllowlist', 'Test-NLSControlTeamsLiveEvents',

    # ── Evaluators — Purview ──────────────────────────────────────────────────
    'Test-NLSControlPurview',
    'Test-NLSControlPurviewAuditSearch', 'Test-NLSControlPurviewCommCompliance',
    'Test-NLSControlPurviewInfoBarriers', 'Test-NLSControlPurviewInsiderRisk',
    'Test-NLSControlPurviewRetention', 'Test-NLSControlPurviewAutoLabel',
    'Test-NLSControlPurviewSIEMExport', 'Test-NLSControlPurviewEDiscovery',
    'Test-NLSControlPurviewComplianceScore', 'Test-NLSControlPurviewSensitiveInfoTypes',
    'Test-NLSControlPurviewAuditPremium', 'Test-NLSControlPurviewAuditRetention',
    'Test-NLSControlPurviewLabelsPublished', 'Test-NLSControlPurviewRecordsManagement',

    # ── Evaluators — Intune ───────────────────────────────────────────────────
    'Test-NLSControlIntune',
    'Test-NLSControlIntuneEDR', 'Test-NLSControlIntuneASR',
    'Test-NLSControlIntuneFirewall', 'Test-NLSControlIntuneMacEncryption',
    'Test-NLSControlIntuneWindowsUpdate', 'Test-NLSControlIntuneEnrollmentRestrictions',
    'Test-NLSControlIntuneAppConfig', 'Test-NLSControlIntuneConditionalLaunch',
    'Test-NLSControlIntuneWindowsLAPS', 'Test-NLSControlIntuneWindowsHello',
    'Test-NLSControlIntuneUpdateCompliance', 'Test-NLSControlIntuneMobilePIN',

    # ── Evaluators — Power Platform ───────────────────────────────────────────
    'Test-NLSControlPowerPlatform',
    'Test-NLSControlPPLConnectorClassification',
    'Test-NLSControlPPLAutomate', 'Test-NLSControlPPLPowerApps',

    # ── Evaluators — Inventory / Object-level ─────────────────────────────────
    'Test-NLSControlInventoryMFAUsers', 'Test-NLSControlInventoryStaleGuests',
    'Test-NLSControlInventoryStaleMembers', 'Test-NLSControlInventoryOAuthApps',
    'Test-NLSControlInventoryExternalForwarding',
    'Test-NLSControlInventorySharedMailboxSignIn',
    'Test-NLSControlInventoryMailboxAuditDisabled',
    'Test-NLSControlInventorySMTPAuthUsers', 'Test-NLSControlInventorySecureScore',

    # ── Evaluators — AI / Copilot ─────────────────────────────────────────────
    'Test-NLSControlAICopilotSensitivityLabels', 'Test-NLSControlAICopilotDLP',
    'Test-NLSControlAICopilotLicensedOnly', 'Test-NLSControlAICopilotStudio',
    'Test-NLSControlAICopilotInteractionData',

    # ── Publishers ────────────────────────────────────────────────────────────
    'Publish-NLSAssessmentHTML', 'Publish-NLSAssessmentSummary',
    'Publish-NLSRemediationPlaybook', 'Publish-NLSRemediationScript',
    'Publish-NLSComplianceMatrix', 'Publish-NLSDeltaReport'
)

Export-ModuleMember -Function $script:ExportedFunctions -Variable NLSAssessmentVersion, NLSBrand
