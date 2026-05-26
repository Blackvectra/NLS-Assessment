#Requires -Version 7.0
#
# Test-NLSControlTeams.ps1
# Evaluates Microsoft Teams controls. Reads: Get-NLSRawData -Key 'Teams'
#
# Controls:
#   TMS-1.1  External federation restricted (not allow-all)
#   TMS-1.2  Anonymous meeting join controlled
#   TMS-1.3  Consumer Teams access restricted
#   TMS-1.4  Auto-admit policy is not 'everyone'
#   TMS-1.5  Cloud storage integrations restricted
#   TMS-1.6  External participant request-control disabled
#

function Test-NLSControlTeams {
    [CmdletBinding()] param()
    $raw = Get-NLSRawData -Key 'Teams'
    if (-not $raw -or -not $raw.Success) {
        foreach ($cid in @('TMS-1.1','TMS-1.3','TMS-1.2','TMS-1.4','TMS-1.5','TMS-1.6')) {
            $c = Get-NLSControlById -ControlId $cid
            if ($c) {
                Add-NLSFinding -ControlId $cid -State 'NotApplicable' `
                    -Category 'Teams' -Title $c.Title `
                    -Detail 'Teams collector did not run.'
            }
        }
        return
    }

    $d = $raw.Data
    $fed   = $d.FederationConfig
    $meet  = $d.MeetingPolicy
    $cli   = $d.ClientConfiguration

    # TMS-1.1 — External federation
    $c = Get-NLSControlById -ControlId 'TMS-1.1'
    if ($c) {
        if (-not $fed) {
            Add-NLSFinding -ControlId 'TMS-1.1' -State 'NotApplicable' `
                -Category 'Teams' -Title $c.Title -Detail 'Federation config unavailable.'
        } elseif ($fed.AllowFederatedUsers -eq $false) {
            Add-NLSFinding -ControlId 'TMS-1.1' -State 'Satisfied' `
                -Category 'Teams' -Title $c.Title -Severity 'Informational' `
                -CurrentValue 'External federation: disabled'
        } elseif ($fed.AllowedDomains.Count -gt 0) {
            Add-NLSFinding -ControlId 'TMS-1.1' -State 'Satisfied' `
                -Category 'Teams' -Title $c.Title -Severity 'Informational' `
                -CurrentValue "Federation restricted to $($fed.AllowedDomains.Count) domain(s)"
        } else {
            Add-NLSFinding -ControlId 'TMS-1.1' -State 'Gap' `
                -Category 'Teams' -Title $c.Title -Severity $c.Severity `
                -Detail 'Federation enabled with no allow-list — any Teams tenant can communicate with users in this tenant.' `
                -CurrentValue 'Allow all external domains' `
                -RequiredValue 'Allow-list of trusted domains, or federation disabled' `
                -Remediation $c.Remediation `
                -FrameworkIds (Get-NLSFrameworkCitations -ControlId 'TMS-1.1')
        }
    }

    # TMS-1.3 — Anonymous meeting join
    $c = Get-NLSControlById -ControlId 'TMS-1.3'
    if ($c) {
        if (-not $meet) {
            Add-NLSFinding -ControlId 'TMS-1.3' -State 'NotApplicable' `
                -Category 'Teams' -Title $c.Title -Detail 'Meeting policy unavailable.'
        } elseif ($meet.AllowAnonymousUsersToJoinMeeting -eq $false) {
            Add-NLSFinding -ControlId 'TMS-1.3' -State 'Satisfied' `
                -Category 'Teams' -Title $c.Title -Severity 'Informational' `
                -CurrentValue 'Anonymous join: blocked'
        } else {
            Add-NLSFinding -ControlId 'TMS-1.3' -State 'Partial' `
                -Category 'Teams' -Title $c.Title -Severity 'Medium' `
                -Detail 'Anonymous users can join meetings. Combined with auto-admit settings this can expose meetings to unauthenticated attendees.' `
                -Remediation $c.Remediation `
                -FrameworkIds (Get-NLSFrameworkCitations -ControlId 'TMS-1.3')
        }
    }

    # TMS-1.2 — Consumer Teams access (was swapped)
    $c = Get-NLSControlById -ControlId 'TMS-1.2'
    if ($c) {
        if (-not $fed) {
            Add-NLSFinding -ControlId 'TMS-1.2' -State 'NotApplicable' `
                -Category 'Teams' -Title $c.Title -Detail 'Federation config unavailable.'
        } elseif ($fed.AllowTeamsConsumer -eq $false) {
            Add-NLSFinding -ControlId 'TMS-1.2' -State 'Satisfied' `
                -Category 'Teams' -Title $c.Title -Severity 'Informational' `
                -CurrentValue 'Consumer Teams: blocked'
        } else {
            Add-NLSFinding -ControlId 'TMS-1.2' -State 'Partial' `
                -Category 'Teams' -Title $c.Title -Severity 'Medium' `
                -Detail 'Consumer (personal) Teams accounts can contact users in this tenant.' `
                -Remediation $c.Remediation `
                -FrameworkIds (Get-NLSFrameworkCitations -ControlId 'TMS-1.2')
        }
    }

    # TMS-1.4 — Auto-admit
    $c = Get-NLSControlById -ControlId 'TMS-1.4'
    if ($c) {
        if (-not $meet) {
            Add-NLSFinding -ControlId 'TMS-1.4' -State 'NotApplicable' `
                -Category 'Teams' -Title $c.Title -Detail 'Meeting policy unavailable.'
        } elseif ($meet.AutoAdmittedUsers -in @('OrganizerOnly','InvitedUsers','EveryoneInCompany','EveryoneInSameAndFederatedCompany')) {
            Add-NLSFinding -ControlId 'TMS-1.4' -State 'Satisfied' `
                -Category 'Teams' -Title $c.Title -Severity 'Informational' `
                -CurrentValue "Auto-admit: $($meet.AutoAdmittedUsers)"
        } else {
            Add-NLSFinding -ControlId 'TMS-1.4' -State 'Gap' `
                -Category 'Teams' -Title $c.Title -Severity $c.Severity `
                -Detail "Auto-admit set to '$($meet.AutoAdmittedUsers)' — uncontrolled attendees bypass the lobby." `
                -CurrentValue "AutoAdmittedUsers = $($meet.AutoAdmittedUsers)" `
                -RequiredValue 'OrganizerOnly or InvitedUsers' `
                -Remediation $c.Remediation `
                -FrameworkIds (Get-NLSFrameworkCitations -ControlId 'TMS-1.4')
        }
    }

    # TMS-1.5 — Cloud storage integrations
    $c = Get-NLSControlById -ControlId 'TMS-1.5'
    if ($c) {
        if (-not $cli) {
            Add-NLSFinding -ControlId 'TMS-1.5' -State 'NotApplicable' `
                -Category 'Teams' -Title $c.Title -Detail 'Client config unavailable.'
        } else {
            $thirdParty = @()
            if ($cli.AllowDropBox)     { $thirdParty += 'Dropbox' }
            if ($cli.AllowBox)         { $thirdParty += 'Box' }
            if ($cli.AllowGoogleDrive) { $thirdParty += 'Google Drive' }
            if ($cli.AllowShareFile)   { $thirdParty += 'ShareFile' }
            if ($thirdParty.Count -eq 0) {
                Add-NLSFinding -ControlId 'TMS-1.5' -State 'Satisfied' `
                    -Category 'Teams' -Title $c.Title -Severity 'Informational' `
                    -CurrentValue 'Only OneDrive/SharePoint allowed'
            } else {
                Add-NLSFinding -ControlId 'TMS-1.5' -State 'Partial' `
                    -Category 'Teams' -Title $c.Title -Severity 'Medium' `
                    -Detail "Third-party cloud storage allowed: $($thirdParty -join ', '). Data can flow to non-corporate storage." `
                    -Remediation $c.Remediation `
                    -FrameworkIds (Get-NLSFrameworkCitations -ControlId 'TMS-1.5')
            }
        }
    }

    # TMS-1.6 — External participant give request control
    $c = Get-NLSControlById -ControlId 'TMS-1.6'
    if ($c) {
        if (-not $meet) {
            Add-NLSFinding -ControlId 'TMS-1.6' -State 'NotApplicable' `
                -Category 'Teams' -Title $c.Title -Detail 'Meeting policy unavailable.'
        } elseif ($meet.AllowExternalParticipantGiveRequestControl -eq $false) {
            Add-NLSFinding -ControlId 'TMS-1.6' -State 'Satisfied' `
                -Category 'Teams' -Title $c.Title -Severity 'Informational' `
                -CurrentValue 'External request-control: blocked'
        } else {
            Add-NLSFinding -ControlId 'TMS-1.6' -State 'Partial' `
                -Category 'Teams' -Title $c.Title -Severity 'Medium' `
                -Detail 'External participants can request remote control during meetings. Disable unless required for specific scenarios.' `
                -Remediation $c.Remediation `
                -FrameworkIds (Get-NLSFrameworkCitations -ControlId 'TMS-1.6')
        }
    }
}

# ── TMS-2.1 Skype User Contact Disabled ──────────────────────────────────────
function Test-NLSControlTeamsSkype {
    [CmdletBinding()] param()
    $cid = 'TMS-2.1'; $ctrl = Get-NLSControlById -ControlId $cid; if (-not $ctrl) { return }
    $cit = Get-NLSFrameworkCitations -ControlId $cid
    $tms = Get-NLSRawData -Key 'Teams'
    if (-not $tms -or -not $tms.Success) { Add-NLSFinding -ControlId $cid -State 'NotApplicable' -Category $ctrl.Category -Title $ctrl.Title -Detail 'Teams data not collected'; return }
    $skype = Get-NLSNestedProperty -Object $tms -Path 'Data.TenantConfig.AllowPublicUsers' -Default $true
    if (-not $skype) {
        Add-NLSFinding -ControlId $cid -State 'Satisfied' -Category $ctrl.Category -Title $ctrl.Title -Severity 'Informational' -FrameworkIds $cit -Detail 'Contact from Skype consumer users is disabled.'
    } else {
        Add-NLSFinding -ControlId $cid -State 'Gap' -Category $ctrl.Category -Title $ctrl.Title -Severity $ctrl.Severity -FrameworkIds $cit -Detail 'Skype consumer users can contact your organization via Teams. Unverifiable external identities with no audit trail.' -Remediation $ctrl.Remediation
    }
}

# ── TMS-2.2 Unverified App Publisher Blocked ─────────────────────────────────
function Test-NLSControlTeamsUnverifiedApps {
    [CmdletBinding()] param()
    $cid = 'TMS-2.2'; $ctrl = Get-NLSControlById -ControlId $cid; if (-not $ctrl) { return }
    $cit = Get-NLSFrameworkCitations -ControlId $cid
    $tms = Get-NLSRawData -Key 'Teams'
    if (-not $tms -or -not $tms.Success) { Add-NLSFinding -ControlId $cid -State 'NotApplicable' -Category $ctrl.Category -Title $ctrl.Title -Detail 'Teams data not collected'; return }
    $allowAll = Get-NLSNestedProperty -Object $tms -Path 'Data.AppConfig.AllowAllApps' -Default $true
    if (-not $allowAll) {
        Add-NLSFinding -ControlId $cid -State 'Satisfied' -Category $ctrl.Category -Title $ctrl.Title -Severity 'Informational' -FrameworkIds $cit -Detail 'Teams app installation restricted — not all apps are allowed.'
    } else {
        Add-NLSFinding -ControlId $cid -State 'Partial' -Category $ctrl.Category -Title $ctrl.Title -Severity 'Medium' -FrameworkIds $cit -Detail 'All Teams apps allowed including those from unverified publishers. Configure an app permission policy to restrict to Microsoft and verified third-party apps only.' -Remediation $ctrl.Remediation
    }
}

# ── TMS-2.3 Third-Party App Storage Disabled ─────────────────────────────────
function Test-NLSControlTeams3PStorage {
    [CmdletBinding()] param()
    $cid = 'TMS-2.3'; $ctrl = Get-NLSControlById -ControlId $cid; if (-not $ctrl) { return }
    $cit = Get-NLSFrameworkCitations -ControlId $cid
    $tms = Get-NLSRawData -Key 'Teams'
    if (-not $tms -or -not $tms.Success) { Add-NLSFinding -ControlId $cid -State 'NotApplicable' -Category $ctrl.Category -Title $ctrl.Title -Detail 'Teams data not collected'; return }
    $dropbox = Get-NLSNestedProperty -Object $tms -Path 'Data.ClientConfig.AllowDropbox' -Default $false
    $box     = Get-NLSNestedProperty -Object $tms -Path 'Data.ClientConfig.AllowBox' -Default $false
    $gdrive  = Get-NLSNestedProperty -Object $tms -Path 'Data.ClientConfig.AllowGoogleDrive' -Default $false
    $sfile   = Get-NLSNestedProperty -Object $tms -Path 'Data.ClientConfig.AllowShareFile' -Default $false
    $anyStorage = [bool]($dropbox -or $box -or $gdrive -or $sfile)
    if (-not $anyStorage) {
        Add-NLSFinding -ControlId $cid -State 'Satisfied' -Category $ctrl.Category -Title $ctrl.Title -Severity 'Informational' -FrameworkIds $cit -Detail 'Third-party cloud storage integrations disabled in Teams.'
    } else {
        Add-NLSFinding -ControlId $cid -State 'Gap' -Category $ctrl.Category -Title $ctrl.Title -Severity $ctrl.Severity -FrameworkIds $cit -Detail 'Third-party cloud storage (Dropbox, Box, Google Drive, or ShareFile) is enabled in Teams. Organizational files can be moved to unmanaged storage.' -Remediation $ctrl.Remediation
    }
}

# ── TMS-2.4 Teams Email Integration Disabled ─────────────────────────────────
function Test-NLSControlTeamsEmailIntegration {
    [CmdletBinding()] param()
    $cid = 'TMS-2.4'; $ctrl = Get-NLSControlById -ControlId $cid; if (-not $ctrl) { return }
    $cit = Get-NLSFrameworkCitations -ControlId $cid
    $tms = Get-NLSRawData -Key 'Teams'
    if (-not $tms -or -not $tms.Success) { Add-NLSFinding -ControlId $cid -State 'NotApplicable' -Category $ctrl.Category -Title $ctrl.Title -Detail 'Teams data not collected'; return }
    $emailInt = Get-NLSNestedProperty -Object $tms -Path 'Data.TenantConfig.AllowEmailIntoChannels' -Default $true
    if (-not $emailInt) {
        Add-NLSFinding -ControlId $cid -State 'Satisfied' -Category $ctrl.Category -Title $ctrl.Title -Severity 'Informational' -FrameworkIds $cit -Detail 'Email integration into Teams channels is disabled.'
    } else {
        Add-NLSFinding -ControlId $cid -State 'Gap' -Category $ctrl.Category -Title $ctrl.Title -Severity $ctrl.Severity -FrameworkIds $cit -Detail 'Email can be sent directly into Teams channels. Channel email addresses bypass email filtering — phishing payloads can be injected directly into Teams.' -Remediation $ctrl.Remediation
    }
}

# ── TMS-2.5 Cloud Recording Disabled for External ────────────────────────────
function Test-NLSControlTeamsRecordingExternal {
    [CmdletBinding()] param()
    $cid = 'TMS-2.5'; $ctrl = Get-NLSControlById -ControlId $cid; if (-not $ctrl) { return }
    $cit = Get-NLSFrameworkCitations -ControlId $cid
    $tms = Get-NLSRawData -Key 'Teams'
    if (-not $tms -or -not $tms.Success) { Add-NLSFinding -ControlId $cid -State 'NotApplicable' -Category $ctrl.Category -Title $ctrl.Title -Detail 'Teams data not collected'; return }
    $allowExtRecord = Get-NLSNestedProperty -Object $tms -Path 'Data.MeetingPolicy.AllowCloudRecordingForCalls' -Default $true
    if (-not $allowExtRecord) {
        Add-NLSFinding -ControlId $cid -State 'Satisfied' -Category $ctrl.Category -Title $ctrl.Title -Severity 'Informational' -FrameworkIds $cit -Detail 'External participants cannot initiate cloud recordings.'
    } else {
        Add-NLSFinding -ControlId $cid -State 'Partial' -Category $ctrl.Category -Title $ctrl.Title -Severity 'Low' -FrameworkIds $cit -Detail 'Cloud recording may be available to external participants. Verify meeting policy AllowCloudRecordingForCalls scoped to internal users only.' -Remediation $ctrl.Remediation
    }
}

# ── TMS-2.6 Broad Channel Meeting Invite Disabled ────────────────────────────
function Test-NLSControlTeamsBroadChannel {
    [CmdletBinding()] param()
    $cid = 'TMS-2.6'; $ctrl = Get-NLSControlById -ControlId $cid; if (-not $ctrl) { return }
    $cit = Get-NLSFrameworkCitations -ControlId $cid
    $tms = Get-NLSRawData -Key 'Teams'
    if (-not $tms -or -not $tms.Success) { Add-NLSFinding -ControlId $cid -State 'NotApplicable' -Category $ctrl.Category -Title $ctrl.Title -Detail 'Teams data not collected'; return }
    $broadInvite = Get-NLSNestedProperty -Object $tms -Path 'Data.MeetingPolicy.AllowChannelMeetingScheduling' -Default $true
    if (-not $broadInvite) {
        Add-NLSFinding -ControlId $cid -State 'Satisfied' -Category $ctrl.Category -Title $ctrl.Title -Severity 'Informational' -FrameworkIds $cit -Detail 'Broad channel meeting scheduling restricted.'
    } else {
        Add-NLSFinding -ControlId $cid -State 'Partial' -Category $ctrl.Category -Title $ctrl.Title -Severity 'Low' -FrameworkIds $cit -Detail 'Channel meeting scheduling enabled — meetings can inadvertently invite all channel members including guests. Review channel membership before enabling.' -Remediation $ctrl.Remediation
    }
}

# ── TMS-2.7 Chat with External Users Restricted ──────────────────────────────
function Test-NLSControlTeamsExternalChat {
    [CmdletBinding()] param()
    $cid = 'TMS-2.7'; $ctrl = Get-NLSControlById -ControlId $cid; if (-not $ctrl) { return }
    $cit = Get-NLSFrameworkCitations -ControlId $cid
    $tms = Get-NLSRawData -Key 'Teams'
    if (-not $tms -or -not $tms.Success) { Add-NLSFinding -ControlId $cid -State 'NotApplicable' -Category $ctrl.Category -Title $ctrl.Title -Detail 'Teams data not collected'; return }
    $extChat = Get-NLSNestedProperty -Object $tms -Path 'Data.TenantConfig.AllowFederatedUsers' -Default $true
    if (-not $extChat) {
        Add-NLSFinding -ControlId $cid -State 'Satisfied' -Category $ctrl.Category -Title $ctrl.Title -Severity 'Informational' -FrameworkIds $cit -Detail 'External user chat is disabled.'
    } else {
        Add-NLSFinding -ControlId $cid -State 'Partial' -Category $ctrl.Category -Title $ctrl.Title -Severity 'Medium' -FrameworkIds $cit -Detail 'External users can initiate chats with internal users. Social engineering via direct Teams message bypasses email security controls.' -Remediation $ctrl.Remediation
    }
}

# ── TMS-2.8 PSTN Dial-Out Restricted ────────────────────────────────────────
function Test-NLSControlTeamsPSTN {
    [CmdletBinding()] param()
    $cid = 'TMS-2.8'; $ctrl = Get-NLSControlById -ControlId $cid; if (-not $ctrl) { return }
    $cit = Get-NLSFrameworkCitations -ControlId $cid
    $tms = Get-NLSRawData -Key 'Teams'
    if (-not $tms -or -not $tms.Success) { Add-NLSFinding -ControlId $cid -State 'NotApplicable' -Category $ctrl.Category -Title $ctrl.Title -Detail 'Teams data not collected'; return }
    $pstn = Get-NLSNestedProperty -Object $tms -Path 'Data.MeetingPolicy.AllowPSTNUsersToBypassLobby' -Default $false
    if (-not $pstn) {
        Add-NLSFinding -ControlId $cid -State 'Satisfied' -Category $ctrl.Category -Title $ctrl.Title -Severity 'Informational' -FrameworkIds $cit -Detail 'PSTN dial-out users cannot bypass lobby.'
    } else {
        Add-NLSFinding -ControlId $cid -State 'Gap' -Category $ctrl.Category -Title $ctrl.Title -Severity $ctrl.Severity -FrameworkIds $cit -Detail 'PSTN users can bypass the Teams meeting lobby. Unverified phone callers can join meetings without approval.' -Remediation $ctrl.Remediation
    }
}

# ── TMS-3.1 Teams Meeting Watermarks Enabled ─────────────────────────────────
function Test-NLSControlTeamsWatermarks {
    [CmdletBinding()] param()
    $cid = 'TMS-3.1'; $ctrl = Get-NLSControlById -ControlId $cid; if (-not $ctrl) { return }
    $cit = Get-NLSFrameworkCitations -ControlId $cid
    $tms = Get-NLSRawData -Key 'Teams'
    if (-not $tms -or -not $tms.Success) {
        Add-NLSFinding -ControlId $cid -State 'NotApplicable' -Category $ctrl.Category `
            -Title $ctrl.Title -Detail 'Teams data not collected'; return
    }
    $watermark = Get-NLSNestedProperty -Object $tms -Path 'Data.MeetingPolicy.AllowWatermarkForScreenSharing' -Default $false
    if ($watermark) {
        Add-NLSFinding -ControlId $cid -State 'Satisfied' -Category $ctrl.Category `
            -Title $ctrl.Title -Severity 'Informational' -FrameworkIds $cit `
            -Detail 'Meeting content watermarking enabled — screen shares include participant identity watermark.'
    } else {
        Add-NLSFinding -ControlId $cid -State 'Partial' -Category $ctrl.Category `
            -Title $ctrl.Title -Severity 'Low' -FrameworkIds $cit `
            -Detail 'Meeting watermarks not enabled. Leaked screenshots or recordings cannot be traced to the participant who shared them.' `
            -Remediation $ctrl.Remediation
    }
}

# ── TMS-3.2 Auto-Admit Only Organization Users ────────────────────────────────
function Test-NLSControlTeamsAutoAdmit {
    [CmdletBinding()] param()
    $cid = 'TMS-3.2'; $ctrl = Get-NLSControlById -ControlId $cid; if (-not $ctrl) { return }
    $cit = Get-NLSFrameworkCitations -ControlId $cid
    $tms = Get-NLSRawData -Key 'Teams'
    if (-not $tms -or -not $tms.Success) {
        Add-NLSFinding -ControlId $cid -State 'NotApplicable' -Category $ctrl.Category `
            -Title $ctrl.Title -Detail 'Teams data not collected'; return
    }
    $autoAdmit = [string](Get-NLSNestedProperty -Object $tms -Path 'Data.MeetingPolicy.AutoAdmittedUsers' -Default 'Everyone')
    $secure    = @('EveryoneInCompanyExcludingGuests','EveryoneInCompany','EveryoneInSameAndFederatedCompany','OrganizerOnly')
    if ($autoAdmit -in $secure) {
        Add-NLSFinding -ControlId $cid -State 'Satisfied' -Category $ctrl.Category `
            -Title $ctrl.Title -Severity 'Informational' -FrameworkIds $cit `
            -Detail "Auto-admit setting: $autoAdmit — external participants must wait in lobby."
    } else {
        Add-NLSFinding -ControlId $cid -State 'Gap' -Category $ctrl.Category `
            -Title $ctrl.Title -Severity $ctrl.Severity -FrameworkIds $cit `
            -Detail "Auto-admit is '$autoAdmit' — anonymous and external users join meetings without lobby admission." `
            -CurrentValue "AutoAdmittedUsers = $autoAdmit" `
            -RequiredValue 'EveryoneInCompanyExcludingGuests or more restrictive' -Remediation $ctrl.Remediation
    }
}

# ── TMS-3.3 Meeting Chat Managed for External Users ─────────────────────────
function Test-NLSControlTeamsMeetingChat {
    [CmdletBinding()] param()
    $cid = 'TMS-3.3'; $ctrl = Get-NLSControlById -ControlId $cid; if (-not $ctrl) { return }
    $cit = Get-NLSFrameworkCitations -ControlId $cid
    $tms = Get-NLSRawData -Key 'Teams'
    if (-not $tms -or -not $tms.Success) {
        Add-NLSFinding -ControlId $cid -State 'NotApplicable' -Category $ctrl.Category `
            -Title $ctrl.Title -Detail 'Teams data not collected'; return
    }
    $chatEnabled = [string](Get-NLSNestedProperty -Object $tms -Path 'Data.MeetingPolicy.AllowMeetingChat' -Default 'Enabled')
    if ($chatEnabled -eq 'Disabled') {
        Add-NLSFinding -ControlId $cid -State 'Satisfied' -Category $ctrl.Category `
            -Title $ctrl.Title -Severity 'Informational' -FrameworkIds $cit `
            -Detail 'Meeting chat is disabled.'
    } elseif ($chatEnabled -eq 'EnabledExceptAnonymous') {
        Add-NLSFinding -ControlId $cid -State 'Satisfied' -Category $ctrl.Category `
            -Title $ctrl.Title -Severity 'Informational' -FrameworkIds $cit `
            -Detail 'Meeting chat enabled for authenticated users only — anonymous participants cannot use chat.'
    } else {
        Add-NLSFinding -ControlId $cid -State 'Partial' -Category $ctrl.Category `
            -Title $ctrl.Title -Severity 'Low' -FrameworkIds $cit `
            -Detail 'Meeting chat enabled for all participants including anonymous. Consider EnabledExceptAnonymous.' `
            -CurrentValue "AllowMeetingChat = $chatEnabled" -RequiredValue 'EnabledExceptAnonymous or Disabled'
    }
}

# ── TMS-3.4 Prevent Copying Meeting Chat ─────────────────────────────────────
function Test-NLSControlTeamsChatCopy {
    [CmdletBinding()] param()
    $cid = 'TMS-3.4'; $ctrl = Get-NLSControlById -ControlId $cid; if (-not $ctrl) { return }
    $cit = Get-NLSFrameworkCitations -ControlId $cid
    $tms = Get-NLSRawData -Key 'Teams'
    if (-not $tms -or -not $tms.Success) {
        Add-NLSFinding -ControlId $cid -State 'NotApplicable' -Category $ctrl.Category `
            -Title $ctrl.Title -Detail 'Teams data not collected'; return
    }
    # v4.6.4 ADVISORY MARK: no programmatic check, manual review required.
    Add-NLSFinding -ControlId $cid -State 'Partial' -Category $ctrl.Category `
        -Title "$($ctrl.Title) (Manual review required)" -Severity 'Low' -FrameworkIds $cit `
        -Detail 'ADVISORY ONLY — no programmatic check is implemented for this control (v4.6.4). Chat copy prevention requires Information Protection policy with DLP. Verify via Purview > DLP > Teams policies if chat content exfiltration prevention is required.' `
        -Remediation $ctrl.Remediation
}

# ── TMS-4.1 Meeting Recording Storage and Permissions Scoped ─────────────────
function Test-NLSControlTeamsMeetingRecordingScope {
    [CmdletBinding()] param()
    $cid = 'TMS-4.1'; $ctrl = Get-NLSControlById -ControlId $cid; if (-not $ctrl) { return }
    $cit = Get-NLSFrameworkCitations -ControlId $cid
    $tms = Get-NLSRawData -Key 'Teams'
    if (-not $tms -or -not $tms.Success) { Add-NLSFinding -ControlId $cid -State 'NotApplicable' -Category $ctrl.Category -Title $ctrl.Title -Detail 'Teams data not collected'; return }
    $expireDays = [int](Get-NLSNestedProperty -Object $tms -Path 'Data.MeetingPolicy.MeetingRecordingExpirationDays' -Default -1)
    if ($expireDays -gt 0 -and $expireDays -le 120) {
        Add-NLSFinding -ControlId $cid -State 'Satisfied' -Category $ctrl.Category -Title $ctrl.Title -Severity 'Informational' -FrameworkIds $cit -Detail "Meeting recordings expire after $expireDays days. Limits long-term exposure of recorded meeting content."
    } elseif ($expireDays -gt 120) {
        Add-NLSFinding -ControlId $cid -State 'Partial' -Category $ctrl.Category -Title $ctrl.Title -Severity 'Low' -FrameworkIds $cit -Detail "Meeting recording expiration set to $expireDays days — consider reducing to 60-90 days." -CurrentValue "$expireDays days" -RequiredValue '≤90 days'
    } else {
        Add-NLSFinding -ControlId $cid -State 'Gap' -Category $ctrl.Category -Title $ctrl.Title -Severity $ctrl.Severity -FrameworkIds $cit -Detail 'Meeting recordings do not expire. Sensitive meeting content persists indefinitely in OneDrive/SharePoint.' -Remediation $ctrl.Remediation
    }
}

# ── TMS-4.2 Anonymous Users Cannot Start Meetings ────────────────────────────
function Test-NLSControlTeamsAnonymousStart {
    [CmdletBinding()] param()
    $cid = 'TMS-4.2'; $ctrl = Get-NLSControlById -ControlId $cid; if (-not $ctrl) { return }
    $cit = Get-NLSFrameworkCitations -ControlId $cid
    $tms = Get-NLSRawData -Key 'Teams'
    if (-not $tms -or -not $tms.Success) { Add-NLSFinding -ControlId $cid -State 'NotApplicable' -Category $ctrl.Category -Title $ctrl.Title -Detail 'Teams data not collected'; return }
    $anonStart = [bool](Get-NLSNestedProperty -Object $tms -Path 'Data.MeetingPolicy.AllowAnonymousUsersToStartMeeting' -Default $true)
    if (-not $anonStart) {
        Add-NLSFinding -ControlId $cid -State 'Satisfied' -Category $ctrl.Category -Title $ctrl.Title -Severity 'Informational' -FrameworkIds $cit -Detail 'Anonymous users cannot start Teams meetings independently.'
    } else {
        Add-NLSFinding -ControlId $cid -State 'Gap' -Category $ctrl.Category -Title $ctrl.Title -Severity $ctrl.Severity -FrameworkIds $cit -Detail 'Anonymous users can start meetings. Unidentified external users can initiate calls into your organization.' -CurrentValue 'AllowAnonymousUsersToStartMeeting = $true' -RequiredValue '$false' -Remediation $ctrl.Remediation
    }
}

# ── TMS-4.3 Federated External Domain Allowlist ───────────────────────────────
function Test-NLSControlTeamsFederationAllowlist {
    [CmdletBinding()] param()
    $cid = 'TMS-4.3'; $ctrl = Get-NLSControlById -ControlId $cid; if (-not $ctrl) { return }
    $cit = Get-NLSFrameworkCitations -ControlId $cid
    $tms = Get-NLSRawData -Key 'Teams'
    if (-not $tms -or -not $tms.Success) { Add-NLSFinding -ControlId $cid -State 'NotApplicable' -Category $ctrl.Category -Title $ctrl.Title -Detail 'Teams data not collected'; return }
    $allowAllDomains = [bool](Get-NLSNestedProperty -Object $tms -Path 'Data.TenantConfig.AllowFederatedUsers' -Default $false)
    $specificDomains = @(Get-NLSNestedProperty -Object $tms -Path 'Data.FederationConfig.AllowedDomains' -Default @())
    if ($allowAllDomains -and $specificDomains.Count -eq 0) {
        Add-NLSFinding -ControlId $cid -State 'Gap' -Category $ctrl.Category -Title $ctrl.Title -Severity $ctrl.Severity -FrameworkIds $cit -Detail 'Teams federation is open to all external domains. Any Teams user at any organization can contact your users.' -CurrentValue 'Open federation — all domains allowed' -RequiredValue 'Allowlist specific trusted domains only' -Remediation $ctrl.Remediation
    } elseif ($allowAllDomains -and $specificDomains.Count -gt 0) {
        Add-NLSFinding -ControlId $cid -State 'Partial' -Category $ctrl.Category -Title $ctrl.Title -Severity 'Medium' -FrameworkIds $cit -Detail "$($specificDomains.Count) specific domain(s) in allowlist but federation is still open. Restrict to allowlist-only mode." -Remediation $ctrl.Remediation
    } else {
        Add-NLSFinding -ControlId $cid -State 'Satisfied' -Category $ctrl.Category -Title $ctrl.Title -Severity 'Informational' -FrameworkIds $cit -Detail 'Teams federation restricted to specific domains or disabled.'
    }
}

# ── TMS-4.4 Live Events Disabled or Restricted ────────────────────────────────
function Test-NLSControlTeamsLiveEvents {
    [CmdletBinding()] param()
    $cid = 'TMS-4.4'; $ctrl = Get-NLSControlById -ControlId $cid; if (-not $ctrl) { return }
    $cit = Get-NLSFrameworkCitations -ControlId $cid
    $tms = Get-NLSRawData -Key 'Teams'
    if (-not $tms -or -not $tms.Success) { Add-NLSFinding -ControlId $cid -State 'NotApplicable' -Category $ctrl.Category -Title $ctrl.Title -Detail 'Teams data not collected'; return }
    $liveEventsEnabled = [bool](Get-NLSNestedProperty -Object $tms -Path 'Data.LiveEventPolicy.AllowBroadcastScheduling' -Default $true)
    $publicEvents      = [bool](Get-NLSNestedProperty -Object $tms -Path 'Data.LiveEventPolicy.AllowBroadcastToAnonymousUsers' -Default $false)
    if ($liveEventsEnabled -and $publicEvents) {
        Add-NLSFinding -ControlId $cid -State 'Gap' -Category $ctrl.Category -Title $ctrl.Title -Severity $ctrl.Severity -FrameworkIds $cit -Detail 'Live events can be broadcast to anonymous (public internet) users. Unrestricted public broadcasting exposes organizational content without authentication.' -CurrentValue 'AllowBroadcastToAnonymousUsers = $true' -RequiredValue '$false' -Remediation $ctrl.Remediation
    } elseif ($liveEventsEnabled) {
        Add-NLSFinding -ControlId $cid -State 'Satisfied' -Category $ctrl.Category -Title $ctrl.Title -Severity 'Informational' -FrameworkIds $cit -Detail 'Live events enabled but anonymous broadcast is disabled. Public internet users cannot watch live events without authentication.'
    } else {
        Add-NLSFinding -ControlId $cid -State 'Satisfied' -Category $ctrl.Category -Title $ctrl.Title -Severity 'Informational' -FrameworkIds $cit -Detail 'Live event scheduling is disabled.'
    }
}