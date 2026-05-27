@{
    # Module identity
    ModuleVersion     = '4.6.5'
    GUID              = 'a1b2c3d4-e5f6-7890-abcd-ef1234567890'
    Author            = 'NextLayerSec'
    CompanyName       = 'NextLayerSec'
    Copyright         = '(c) 2026 NextLayerSec. All rights reserved.'
    Description       = 'Read-only Microsoft 365 security assessment framework for MSPs. Multi-framework, multi-tenant, client-ready reporting.'

    # Runtime requirements
    PowerShellVersion = '7.0'
    CompatiblePSEditions = @('Core')

    # Root module
    RootModule        = 'NLS-Assessment.psm1'

    # All functions exported by this module.
    # IMPORTANT: this list must stay in sync with $script:ExportedFunctions in
    # NLS-Assessment.psm1. PowerShell intersects the two lists, so a function
    # missing here is silently dropped from the exported surface.
    FunctionsToExport = @(
        # ── Lib ───────────────────────────────────────────────────────────────
        'Add-NLSFinding',
        'Get-NLSFindings',
        'Clear-NLSFindings',
        'Clear-NLSState',
        'Register-NLSException',
        'Get-NLSExceptions',
        'Register-NLSCoverage',
        'Get-NLSCoverage',
        'Set-NLSRawData',
        'Get-NLSRawData',
        'Connect-NLSServices',
        'Disconnect-NLSServices',
        'ConvertTo-NLSHtmlSafe',
        'ConvertTo-NLSSafeUrl',
        'Get-NLSControlDefinitions',
        'Get-NLSControlById',
        'Get-NLSFindingRiskCost',
        'Get-NLSAggregateRisk',
        'Get-NLSFrameworkCitations',
        'Get-NLSFrameworkDefinitions',
        'Set-NLSSensitiveFileAcl',
        'Set-NLSSensitiveFileContent',
        'Get-NLSTenantLicenseProfile',
        'Test-NLSLicenseRequirementMet',
        'Get-NLSSafeProperty',
        'Get-NLSNestedProperty',

        # ── Collectors — AAD ──────────────────────────────────────────────────
        'Invoke-NLSCollectAADAuthPolicies',
        'Invoke-NLSCollectAADCAPolicies',
        'Invoke-NLSCollectAADUsers',
        'Invoke-NLSCollectAADRoles',
        'Invoke-NLSCollectAADPIM',
        'Invoke-NLSCollectAADIdentityGovernance',
        'Invoke-NLSCollectAADInventory',

        # ── Collectors — EXO / Defender / DNS ─────────────────────────────────
        'Invoke-NLSCollectEXOMailboxConfig',
        'Invoke-NLSCollectEXOConnectionFilter',
        'Invoke-NLSCollectEXOInventory',
        'Invoke-NLSCollectDefender',
        'Invoke-NLSCollectDNSEmailRecords',

        # ── Collectors — Phase 2+ ─────────────────────────────────────────────
        'Invoke-NLSCollectSharePoint',
        'Invoke-NLSCollectTeams',
        'Invoke-NLSCollectPurview',
        'Invoke-NLSCollectIntuneEndpointSecurity',
        'Invoke-NLSCollectIntuneDeviceCompliance',
        'Invoke-NLSCollectIntuneAppProtection',
        'Invoke-NLSCollectPowerPlatform',
        'Invoke-NLSCollectM365Copilot',

        # ── Evaluators — AAD ──────────────────────────────────────────────────
        'Test-NLSControlAADLegacyAuth',
        'Test-NLSControlAADMFA',
        'Test-NLSControlAADPhishResistantMFA',
        'Test-NLSControlAADCA',
        'Test-NLSControlAADPrivAccess',
        'Test-NLSControlAADSignInRisk',
        'Test-NLSControlAADUserRisk',
        'Test-NLSControlAADNamedLocations',
        'Test-NLSControlAADDeviceComplianceCA',
        'Test-NLSControlAADNoPermanentAdmins',
        'Test-NLSControlAADPIMMFA',
        'Test-NLSControlAADPIMJustification',
        'Test-NLSControlAADPIMApproval',
        'Test-NLSControlAADPIMDuration',
        'Test-NLSControlAADGuestInvite',
        'Test-NLSControlAADExternalCollab',
        'Test-NLSControlAADGuestPermissions',
        'Test-NLSControlAADSSPR',
        'Test-NLSControlAADSSPRMethods',
        'Test-NLSControlAADUserAppReg',
        'Test-NLSControlAADUserConsent',
        'Test-NLSControlAADAdminConsentWorkflow',
        'Test-NLSControlAADPasswordProtection',
        'Test-NLSControlAADBreakGlass',
        'Test-NLSControlAADPIMAlerts',
        'Test-NLSControlAADAccessReviews',
        'Test-NLSControlAADAuthenticatorNumberMatch',
        'Test-NLSControlAADPasswordless',
        'Test-NLSControlAADIdentityProtection',
        'Test-NLSControlAADPrivCloudOnly',
        'Test-NLSControlAADBreakGlassMonitoring',
        'Test-NLSControlAADSignInFrequency',
        'Test-NLSControlAADDeviceCode',
        'Test-NLSControlAADNoGuestInPrivRoles',
        'Test-NLSControlAADRiskyServicePrincipals',
        'Test-NLSControlAADTokenProtection',
        'Test-NLSControlAADContinuousAccess',
        'Test-NLSControlAADCrossTenantAccess',
        'Test-NLSControlAADPrivilegedWorkstation',
        'Test-NLSControlAADTermsOfUse',
        'Test-NLSControlAADWorkloadIdentityCA',

        # ── Evaluators — DNS ──────────────────────────────────────────────────
        'Test-NLSControlDNSSPF',
        'Test-NLSControlDNSDKIM',
        'Test-NLSControlDNSDMARC',
        'Test-NLSControlDNSMTASTS',
        'Test-NLSControlDNSTLSRPT',
        'Test-NLSControlDNSDNSSEC',
        'Test-NLSControlDNSDkimRotation',
        'Test-NLSControlDNSCAA',
        'Test-NLSControlDNSTLSCertExpiry',
        'Test-NLSControlDNSCertTransparency',

        # ── Evaluators — EXO ──────────────────────────────────────────────────
        'Test-NLSControlEXOMailboxAudit',
        'Test-NLSControlEXOSmtpAuth',
        'Test-NLSControlEXOAutoForward',
        'Test-NLSControlEXODKIM',
        'Test-NLSControlEXOAntiPhish',
        'Test-NLSControlEXOModernAuth',
        'Test-NLSControlEXOHonorDMARC',
        'Test-NLSControlEXOPop3',
        'Test-NLSControlEXOImap',
        'Test-NLSControlEXOCustomerLockbox',
        'Test-NLSControlEXOSharedMailbox',
        'Test-NLSControlEXOConnectionFilter',
        'Test-NLSControlEXOOutboundLimits',
        'Test-NLSControlEXOAlertForwarding',
        'Test-NLSControlEXOAlertVolume',
        'Test-NLSControlEXOTransportAudit',
        'Test-NLSControlEXOAuditAgeLimit',
        'Test-NLSControlEXOAdminAudit',
        'Test-NLSControlEXOSafeAttachmentsSPO',
        'Test-NLSControlEXOAntiSpamInbound',
        'Test-NLSControlEXOPerUserAudit',
        'Test-NLSControlEXOPriorityAccountProtection',
        'Test-NLSControlEXOSafeSenderOverride',
        'Test-NLSControlEXOMailboxForwarding',
        'Test-NLSControlEXOInboxRulesForwarding',
        'Test-NLSControlEXOAuditDisabledMailboxes',
        'Test-NLSControlEXOSmtpAuthExceptions',

        # ── Evaluators — Defender ─────────────────────────────────────────────
        'Test-NLSControlDefender',
        'Test-NLSControlDefenderPresetPolicies',
        'Test-NLSControlDefenderZAP',
        'Test-NLSControlDefenderCommonAttachments',
        'Test-NLSControlDefenderQuarantine',
        'Test-NLSControlDefenderHCSpam',
        'Test-NLSControlDefenderBulkThreshold',
        'Test-NLSControlDefenderUnauthSender',
        'Test-NLSControlDefenderViaTag',
        'Test-NLSControlDefenderMDCA',
        'Test-NLSControlDefenderAlertNotification',
        'Test-NLSControlDefenderDLPWorkloads',
        'Test-NLSControlDefenderDLPSITs',
        'Test-NLSControlDefenderRiskyAppAlerts',
        'Test-NLSControlDefenderPriorityAccounts',
        'Test-NLSControlDefenderEndpointDLP',
        'Test-NLSControlDefenderAttackSim',
        'Test-NLSControlDefenderSafeLinksOffice',

        # ── Evaluators — SharePoint ───────────────────────────────────────────
        'Test-NLSControlSharePoint',
        'Test-NLSControlSPOOneDriveSync',
        'Test-NLSControlSPOLinkExpiration',
        'Test-NLSControlSPOAppsFromStore',
        'Test-NLSControlSPOCustomScript',
        'Test-NLSControlSPO3PStorage',
        'Test-NLSControlSPOEmailAttestation',
        'Test-NLSControlSPOReauth',
        'Test-NLSControlSPODomainSync',
        'Test-NLSControlSPOSiteAdmins',
        'Test-NLSControlSPOSharingNotifications',
        'Test-NLSControlSPOVersionHistory',
        'Test-NLSControlSPOGuestExpiry',

        # ── Evaluators — Teams ────────────────────────────────────────────────
        'Test-NLSControlTeams',
        'Test-NLSControlTeamsSkype',
        'Test-NLSControlTeamsUnverifiedApps',
        'Test-NLSControlTeams3PStorage',
        'Test-NLSControlTeamsEmailIntegration',
        'Test-NLSControlTeamsRecordingExternal',
        'Test-NLSControlTeamsBroadChannel',
        'Test-NLSControlTeamsExternalChat',
        'Test-NLSControlTeamsPSTN',
        'Test-NLSControlTeamsWatermarks',
        'Test-NLSControlTeamsAutoAdmit',
        'Test-NLSControlTeamsMeetingChat',
        'Test-NLSControlTeamsChatCopy',
        'Test-NLSControlTeamsMeetingRecordingScope',
        'Test-NLSControlTeamsAnonymousStart',
        'Test-NLSControlTeamsFederationAllowlist',
        'Test-NLSControlTeamsLiveEvents',

        # ── Evaluators — Purview ──────────────────────────────────────────────
        'Test-NLSControlPurview',
        'Test-NLSControlPurviewAuditSearch',
        'Test-NLSControlPurviewCommCompliance',
        'Test-NLSControlPurviewInfoBarriers',
        'Test-NLSControlPurviewInsiderRisk',
        'Test-NLSControlPurviewRetention',
        'Test-NLSControlPurviewAutoLabel',
        'Test-NLSControlPurviewSIEMExport',
        'Test-NLSControlPurviewEDiscovery',
        'Test-NLSControlPurviewComplianceScore',
        'Test-NLSControlPurviewSensitiveInfoTypes',
        'Test-NLSControlPurviewAuditPremium',
        'Test-NLSControlPurviewAuditRetention',
        'Test-NLSControlPurviewLabelsPublished',
        'Test-NLSControlPurviewRecordsManagement',

        # ── Evaluators — Intune ───────────────────────────────────────────────
        'Test-NLSControlIntune',
        'Test-NLSControlIntuneEDR',
        'Test-NLSControlIntuneASR',
        'Test-NLSControlIntuneFirewall',
        'Test-NLSControlIntuneMacEncryption',
        'Test-NLSControlIntuneWindowsUpdate',
        'Test-NLSControlIntuneEnrollmentRestrictions',
        'Test-NLSControlIntuneAppConfig',
        'Test-NLSControlIntuneConditionalLaunch',
        'Test-NLSControlIntuneWindowsLAPS',
        'Test-NLSControlIntuneWindowsHello',
        'Test-NLSControlIntuneUpdateCompliance',
        'Test-NLSControlIntuneMobilePIN',

        # ── Evaluators — Power Platform ───────────────────────────────────────
        'Test-NLSControlPowerPlatform',
        'Test-NLSControlPPLConnectorClassification',
        'Test-NLSControlPPLAutomate',
        'Test-NLSControlPPLPowerApps',

        # ── Evaluators — Inventory ────────────────────────────────────────────
        'Test-NLSControlInventoryMFAUsers',
        'Test-NLSControlInventoryStaleGuests',
        'Test-NLSControlInventoryStaleMembers',
        'Test-NLSControlInventoryOAuthApps',
        'Test-NLSControlInventoryExternalForwarding',
        'Test-NLSControlInventorySharedMailboxSignIn',
        'Test-NLSControlInventoryMailboxAuditDisabled',
        'Test-NLSControlInventorySMTPAuthUsers',
        'Test-NLSControlInventorySecureScore',

        # ── Evaluators — AI / Copilot ─────────────────────────────────────────
        'Test-NLSControlAICopilotSensitivityLabels',
        'Test-NLSControlAICopilotDLP',
        'Test-NLSControlAICopilotLicensedOnly',
        'Test-NLSControlAICopilotStudio',
        'Test-NLSControlAICopilotInteractionData',

        # ── Publishers ────────────────────────────────────────────────────────
        'Publish-NLSAssessmentHTML',
        'Publish-NLSAssessmentSummary',
        'Publish-NLSRemediationPlaybook',
        'Publish-NLSRemediationScript',
        'Publish-NLSComplianceMatrix',
        'Publish-NLSDeltaReport'
    )

    VariablesToExport = @('NLSAssessmentVersion', 'NLSBrand')
    CmdletsToExport   = @()
    AliasesToExport   = @()

    # Required modules — must be present before this module loads.
    # Audit fix (v4.6.x LOW): MicrosoftTeams added because Connect-NLSServices
    # imports it at runtime (Teams collector wraps Get-CsTenant / Get-CsTeams*),
    # and ExchangeOnlineManagement is pinned to the same 3.2.0 floor that
    # Install-NLSPrerequisites enforces (3.4.0+ has the WAM broker
    # NullReferenceException that the prereq script downgrades around).
    RequiredModules = @(
        @{ ModuleName = 'Microsoft.Graph.Authentication'; ModuleVersion = '2.20.0' },
        @{ ModuleName = 'ExchangeOnlineManagement';       ModuleVersion = '3.2.0' },
        @{ ModuleName = 'MicrosoftTeams';                 ModuleVersion = '5.0.0' }
    )

    # Module metadata
    PrivateData = @{
        PSData = @{
            Tags         = @('M365', 'Security', 'Assessment', 'MSP', 'CIS', 'SCuBA', 'NIST', 'CMMC')
            ProjectUri   = 'https://github.com/Blackvectra/NLS-Assessment'
            ReleaseNotes = @'
v4.6.4 EMERGENCY (Part A): orchestrator + Apply + evaluator + control-def fixes.

Critical fixes:
  * Pre-initialize $script:NLSFatalExitCode and $script:NLSSuccessExitCode in
    Invoke-NLSAssessment.ps1 so StrictMode reads at exit never throw on the
    success path (v4.6.3 crashed every successful run with exit code 1 AFTER
    the report was written).
  * Apply-NLSAADMFA + Apply-NLSAADLegacyAuth: replace unguarded
    $_.Conditions.* / $_.GrantControls.* chained access with
    Get-NLSNestedProperty under StrictMode. Prior code blew up the
    idempotency Where-Object scan on the first CA policy with a null nested
    object → DUPLICATE CA policies created on every apply.
  * Test-NLSControl-Inventory.ps1 OAuth INV-1.4: fix
    `$highRisk | Where-Object { $_.AppName -eq $_.AppName }` self-comparison
    (always true) — every OAuth app was tagged [HIGH RISK SCOPE] whenever
    any high-risk app existed. Now uses an actual lookup.

PII fixes (HTML report client-deliverable):
  * EXO-7.4 (SmtpAuthExceptions) and AAD-10.2 (PrivCloudOnly) — move full
    UPN list out of the rendered Detail field into structured
    AffectedObjects (escaped). Detail keeps count only.

Dedupe + advisory marking:
  * Purview triple-counting: PVW-1.1 remains canonical UAL check; PVW-2.1
    repointed to AdminAuditLogEnabled; PVW-3.2 repointed to eDiscovery
    cases (or NotApplicable). A tenant with audit disabled now gets ONE
    Gap finding, not three.
  * 15 placeholder evaluators marked "(Manual review required)" in Title
    and ADVISORY ONLY in Detail until real checks land in v4.7.0. Includes
    SPO-3.3 downgrade from hardcoded Satisfied to NotApplicable.

Control definition fixes (controls.json):
  * 11 fabricated SCuBA pillars cleared (MS.PURVIEW.* on PVW-1.1/1.3/2.1/3.4,
    MS.INTUNE.* on INT-1.1/1.2/2.1/2.5/3.3/4.1/4.3) — those pillars do not
    exist in SCuBA. Set SCuBA = "" with a description note.
  * AAD-1.2 / AAD-1.3 SCuBA citations corrected to current ScubaGear IDs
    (MS.AAD.3.2v2 for MFA-for-all, MS.AAD.3.6v1 for phishing-resistant MFA).
  * EXO-2.7 silent no-op duplicate of EXO-1.6 removed.

License-detection fixes:
  * Get-NLSTenantLicenseProfile.SuppressedLicenseRequirements now handles
    7 controls.json strings that previously drifted out of the map:
    DfO Plan 2 with parenthetical, M365 E5 Compliance add-on, M365 E5 or
    E5 Compliance add-on, Sentinel/Defender XDR, Entra Workload Identities
    Premium, M365 Copilot ($30/user/month), Power Platform + Copilot Studio.
  * Pester unit tests added in Testing/NLS.LicenseDetection.Tests.ps1
    exercising each of the 7 strings.

----- prior release notes -----

v4.6.1: 217 exported functions. Closes Phase 2 + Phase 4 roadmap gaps.

PRs:
  #12 DNS extended evaluators (4 new): DNS-2.1 DkimRotation, DNS-2.2 CAA,
      DNS-2.3 TLSCertExpiry, DNS-2.4 CertTransparency. Consumes the extended
      collector data that was previously unread.
  #13 EXO Inventory evaluators (4 new): EXO-7.1 MailboxForwarding,
      EXO-7.2 InboxRulesForwarding, EXO-7.3 AuditDisabledMailboxes,
      EXO-7.4 SmtpAuthExceptions. Consumes the inventory collector data.
  #14 Framework citations: SCuBA 126→136 (10 honest mappings; 52 marked
      "" with description note where no SCuBA equivalent exists). CMMC
      141→188 (100% via NIST→CMMC L2 standard mapping).
  #15 Copilot governance: new M365Copilot collector (reuses Purview raw
      data; Graph subscribedSkus + users + applications). 5 stub evaluators
      replaced with real logic (sensitivity labels, DLP, licensing ratio,
      Studio external publish, interaction-data retention).
  #16 Apply-NLSBaseline.ps1: interactive write-mode tool with WhatIf,
      idempotency check, rollback log, approval gates. V1 includes 6
      representative apply functions (AAD-1.1 legacy auth, AAD-2.1 MFA,
      EXO-1.1 mailbox audit, EXO-1.2 SMTP AUTH, EXO-1.3 auto-forward,
      DEF-1.1 Defender preset). CA-policy creators deploy in
      enabledForReportingButNotEnforced — operator promotes after sign-in
      log validation.

Test infrastructure fixes:
  * Pester "All evaluators exist" updated for PR #6 file renames.
  * Pester "Read-Only Posture" excludes Apply-NLSBaseline (which IS the
    write-mode tool by design).

Migration: any caller of Invoke-NLSCollectIntune must switch to one of
Invoke-NLSCollectIntuneEndpointSecurity / Invoke-NLSCollectIntuneDeviceCompliance /
Invoke-NLSCollectIntuneAppProtection.
'@
        }
    }
}
